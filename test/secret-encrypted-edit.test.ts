import { proto } from 'baileys';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';

import { decryptMessageEdit, editAuthorJids, toMessageSecret } from '../src/utils/secretEncryptedEdit';

// Synthetic vector — fake ids, JIDs and secret. Produced by a standalone script
// that ENCRYPTS with node:crypto (HKDF-SHA256 + AES-256-GCM), independent from
// the code under test, following the derivation validated on 2026-10-21 against
// a real envelope captured in production:
//   key = HKDF-SHA256(messageSecret, no salt, info = id + authorJid + authorJid + 'Message Edit', 32)
//   AES-256-GCM(key, encIv, encPayload), no AAD → proto.Message { protocolMessage }
const ORIGINAL_ID = '3A0000000000EDIT0001';
const AUTHOR_LID = '111111111111111@lid';
const AUTHOR_PN = '5583999999999@s.whatsapp.net';
const OUR_LID = '222222222222222@lid';
const EDITED_TEXT = 'paciente: Fulana de Tal\nData: 01/01/1990';
const SECRET = Buffer.from('0HG7us4aLYUQEbhW45zD+zQrr+phOCcnexfQ1X60bVk=', 'base64');

// The envelope as the editor wrote it: targetMessageKey is in the EDITOR's point of
// view (fromMe: true, remoteJid: our LID) — exactly how it arrives from WhatsApp.
const envelope: proto.Message.ISecretEncryptedMessage = {
  targetMessageKey: { remoteJid: OUR_LID, fromMe: true, id: ORIGINAL_ID },
  encIv: Buffer.from('bHjDfdNWaFKLfu4Y', 'base64'),
  encPayload: Buffer.from(
    'fXD1MenZyEa4WJ+G3DeWkcRV3Lio3PyZy2NrOhrXs0EsSJnBDeTLsrHsfA4HBQz0/NlncBqwAuewBxWlNbzSOfdRl/pJC5ydhhSrCWnQH70o7q1psiBQfPb5nfMwvFoBTHX19dW8EDrURZHGP8wlSADtTyXPQQ==',
    'base64',
  ),
  secretEncType: proto.Message.SecretEncryptedMessage.SecretEncType.MESSAGE_EDIT,
};

// The upsert key of the envelope as Baileys delivers it on a pn-addressed chat.
const receivedKey = {
  remoteJid: AUTHOR_PN,
  remoteJidAlt: AUTHOR_LID,
  fromMe: false,
  id: '3A00000000000ENVELOPE',
  participant: '',
  addressingMode: 'pn',
};

const decrypt = (overrides: Partial<Parameters<typeof decryptMessageEdit>[0]> = {}) =>
  decryptMessageEdit({
    envelope,
    messageSecret: SECRET,
    authorJids: [receivedKey.remoteJid, receivedKey.remoteJidAlt],
    receivedKey,
    ...overrides,
  });

describe('decryptMessageEdit', () => {
  it('decrypts a MESSAGE_EDIT envelope into the edit protocolMessage', () => {
    const edit = decrypt();

    assert.ok(edit, 'expected the envelope to decrypt');
    assert.equal(edit.type, proto.Message.ProtocolMessage.Type.MESSAGE_EDIT);
    assert.equal(edit.editedMessage?.conversation, EDITED_TEXT);
  });

  it('finds the author among the candidates — the LID authenticates even when the PN comes first', () => {
    assert.ok(decrypt({ authorJids: [AUTHOR_PN, undefined, '', AUTHOR_LID] }));
  });

  it('normalizes device suffixes before deriving the key', () => {
    assert.ok(decrypt({ authorJids: ['111111111111111:27@lid'] }));
  });

  it('returns null when no candidate is the author', () => {
    assert.equal(decrypt({ authorJids: [AUTHOR_PN, OUR_LID] }), null);
  });

  it('returns null for a messageSecret that is not the original one', () => {
    assert.equal(decrypt({ messageSecret: randomBytes(32) }), null);
  });

  it('ignores envelopes that are not a message edit', () => {
    const eventEdit = { ...envelope, secretEncType: proto.Message.SecretEncryptedMessage.SecretEncType.EVENT_EDIT };
    assert.equal(decrypt({ envelope: eventEdit }), null);
  });

  it('returns null when the envelope does not point to an original message', () => {
    assert.equal(decrypt({ envelope: { ...envelope, targetMessageKey: { remoteJid: OUR_LID, fromMe: true } } }), null);
  });

  it("rekeys the edit to the receiver's point of view: original id, envelope chat and direction", () => {
    const edit = decrypt();

    assert.equal(edit?.key?.id, ORIGINAL_ID);
    assert.equal(edit?.key?.remoteJid, AUTHOR_PN);
    assert.equal(edit?.key?.fromMe, false);
  });

  it('serializes to the shape webhook consumers read: data.key.id + data.editedMessage', () => {
    const data = JSON.parse(JSON.stringify(decrypt()));

    assert.equal(data.key.id, ORIGINAL_ID);
    assert.equal(data.type, 'MESSAGE_EDIT');
    assert.equal(data.editedMessage.conversation, EDITED_TEXT);
  });
});

describe('editAuthorJids', () => {
  const OWN = ['5583888888888@s.whatsapp.net', '333333333333333:4@lid', '5583888888888:4@s.whatsapp.net'];

  it('on a direct chat, the author is the contact — in both forms the key carries', () => {
    assert.deepEqual(editAuthorJids(receivedKey, OWN), [AUTHOR_PN, AUTHOR_LID]);
  });

  it('on a group, the author is the participant — never the group JID', () => {
    const groupKey = {
      remoteJid: '120363000000000000@g.us',
      fromMe: false,
      id: 'X',
      participant: AUTHOR_LID,
      participantAlt: AUTHOR_PN,
    };
    assert.deepEqual(editAuthorJids(groupKey, OWN), [AUTHOR_LID, AUTHOR_PN]);
  });

  it('when we edited (fromMe), the author is this account — never the contact', () => {
    assert.deepEqual(editAuthorJids({ ...receivedKey, fromMe: true }, OWN), OWN);
  });
});

describe('toMessageSecret', () => {
  const bytes = Array.from(SECRET);
  const base64 = SECRET.toString('base64');

  it('accepts a Buffer and a Uint8Array', () => {
    assert.deepEqual(toMessageSecret(SECRET), SECRET);
    assert.deepEqual(toMessageSecret(new Uint8Array(SECRET)), SECRET);
  });

  it('accepts base64 text, raw or as the 44-byte buffer it sometimes comes stored as', () => {
    assert.deepEqual(toMessageSecret(base64), SECRET);
    assert.deepEqual(toMessageSecret(Buffer.from(base64, 'utf8')), SECRET);
  });

  it('accepts the JSON forms a stored message takes: Buffer JSON and index-keyed object', () => {
    assert.deepEqual(toMessageSecret({ type: 'Buffer', data: bytes }), SECRET);
    assert.deepEqual(toMessageSecret(JSON.parse(JSON.stringify(new Uint8Array(SECRET)))), SECRET);
  });

  it('returns null for anything that is not a 32-byte secret', () => {
    for (const raw of [undefined, null, '', {}, [], 42, randomBytes(16), { type: 'Buffer', data: [1, 2] }]) {
      assert.equal(toMessageSecret(raw), null, `expected null for ${JSON.stringify(raw)}`);
    }
  });
});
