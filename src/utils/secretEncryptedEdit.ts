import { isJidGroup, jidNormalizedUser, proto, WAMessageKey } from 'baileys';
import { createDecipheriv, hkdfSync } from 'crypto';

// WhatsApp no longer sends message edits in clear: an edit travels as a
// secretEncryptedMessage (secretEncType MESSAGE_EDIT) whose payload is encrypted
// with a key derived from the ORIGINAL message's messageSecret. Baileys rc13 does
// not decrypt it, so edits reached the webhook as an opaque upsert and consumers
// kept showing the text the sender had already corrected.
//
// Derivation validated on 2026-10-21 against real envelopes captured in production:
//   key = HKDF-SHA256(messageSecret, no salt, info = originalId + authorJid + authorJid + 'Message Edit', 32)
//   AES-256-GCM(key, encIv, encPayload), no AAD → proto.Message { protocolMessage: MESSAGE_EDIT }
// The author JID that authenticates is the LID even on pn-addressed chats, and a
// payload may carry either form — so candidates are tried; GCM's tag rejects the
// wrong ones.

const MESSAGE_EDIT_INFO = 'Message Edit';
const SECRET_LENGTH = 32;
const GCM_TAG_LENGTH = 16;

/**
 * The original message's messageSecret, in whatever form it was persisted:
 * Buffer/Uint8Array, base64 text (raw or as the 44-byte buffer of that text),
 * Buffer JSON or the index-keyed object a Uint8Array becomes in JSON.
 */
export function toMessageSecret(raw: unknown): Buffer | null {
  let secret: Buffer | null = null;

  if (typeof raw === 'string') {
    secret = Buffer.from(raw, 'base64');
  } else if (raw instanceof Uint8Array) {
    secret = Buffer.from(raw);
  } else if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    const obj = raw as Record<string, unknown>;
    const keys = Object.keys(obj);

    if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
      secret = Buffer.from(obj.data as number[]);
    } else if (keys.length > 0 && keys.every((k) => /^\d+$/.test(k))) {
      secret = Buffer.from(keys.sort((a, b) => Number(a) - Number(b)).map((k) => Number(obj[k])));
    }
  }

  if (secret?.length === 44) {
    secret = Buffer.from(secret.toString('utf8'), 'base64');
  }

  return secret?.length === SECRET_LENGTH ? secret : null;
}

/**
 * Who authored the edit — only the original's author can edit it. On our own
 * edits that is this account; otherwise the contact (or the group participant),
 * in whichever forms (PN and/or LID) the envelope's key carries.
 */
export function editAuthorJids(receivedKey: WAMessageKey, ownJids: Array<string | null | undefined>): string[] {
  const candidates = receivedKey.fromMe
    ? ownJids
    : isJidGroup(receivedKey.remoteJid ?? undefined)
      ? [receivedKey.participant, receivedKey.participantAlt]
      : [receivedKey.remoteJid, receivedKey.remoteJidAlt];

  return [...new Set(candidates.filter((jid): jid is string => !!jid))];
}

/**
 * Decrypts a MESSAGE_EDIT envelope into the same protocolMessage a clear-text
 * edit carries, rekeyed to the receiver's point of view. Never throws: anything
 * that does not authenticate or decode as an edit returns null, so the caller
 * can keep the envelope's previous handling.
 */
export function decryptMessageEdit({
  envelope,
  messageSecret,
  authorJids,
  receivedKey,
}: {
  envelope: proto.Message.ISecretEncryptedMessage;
  messageSecret: Uint8Array;
  authorJids: Array<string | null | undefined>;
  receivedKey: WAMessageKey;
}): proto.Message.IProtocolMessage | null {
  const originalId = envelope?.targetMessageKey?.id;
  const iv = envelope?.encIv;
  const payload = envelope?.encPayload;

  if (
    envelope?.secretEncType !== proto.Message.SecretEncryptedMessage.SecretEncType.MESSAGE_EDIT ||
    !originalId ||
    !iv?.length ||
    !payload ||
    payload.length <= GCM_TAG_LENGTH
  ) {
    return null;
  }

  const authors = [...new Set(authorJids.filter((jid): jid is string => !!jid).map((jid) => jidNormalizedUser(jid)))];

  for (const originalSender of authors) {
    for (const editor of authors) {
      const info = Buffer.from(`${originalId}${originalSender}${editor}${MESSAGE_EDIT_INFO}`);
      const plaintext = tryDecrypt(messageSecret, info, iv, payload);

      if (plaintext) {
        return toReceiverEdit(plaintext, receivedKey, originalId);
      }
    }
  }

  return null;
}

function tryDecrypt(messageSecret: Uint8Array, info: Buffer, iv: Uint8Array, payload: Uint8Array): Buffer | null {
  const sealed = Buffer.from(payload);

  try {
    const key = Buffer.from(hkdfSync('sha256', messageSecret, Buffer.alloc(0), info, 32));
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(sealed.subarray(sealed.length - GCM_TAG_LENGTH));
    return Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - GCM_TAG_LENGTH)), decipher.final()]);
  } catch {
    return null;
  }
}

function toReceiverEdit(
  plaintext: Buffer,
  receivedKey: WAMessageKey,
  originalId: string,
): proto.Message.IProtocolMessage | null {
  let edit: proto.Message.IProtocolMessage | null | undefined;

  try {
    edit = proto.Message.decode(plaintext).protocolMessage;
  } catch {
    return null;
  }

  if (edit?.type !== proto.Message.ProtocolMessage.Type.MESSAGE_EDIT || !edit.editedMessage) {
    return null;
  }

  // The decrypted key is the EDITOR's view (fromMe: true, remoteJid: our own
  // LID). Same rekeying Baileys applies to clear-text edits: the envelope's
  // chat and direction, with the original message's id.
  edit.key = { ...receivedKey, id: originalId };

  return edit;
}
