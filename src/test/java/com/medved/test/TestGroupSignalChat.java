package com.medved.test;

import static org.junit.Assert.*;

import org.junit.Test;
import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.groups.GroupCipher;
import org.whispersystems.libsignal.groups.GroupSessionBuilder;
import org.whispersystems.libsignal.groups.InMemorySenderKeyStore;
import org.whispersystems.libsignal.groups.SenderKeyName;
import org.whispersystems.libsignal.protocol.SenderKeyDistributionMessage;

public class TestGroupSignalChat {

	private static final String Alice_second_message = "smert ze smert2";
	private static final String Alice_first_message = "smert ze smert";
	private static final SignalProtocolAddress SENDER_ADDRESS = new SignalProtocolAddress("+14150001111", 1);
	private static final SenderKeyName GROUP_SENDER_ALICE = new SenderKeyName("nihilist history reading group", SENDER_ADDRESS);

	private static final SignalProtocolAddress SENDER_ADDRESS_BOB = new SignalProtocolAddress("+14150002222", 1);
	private static final SenderKeyName GROUP_SENDER_BOB = new SenderKeyName("nihilist history reading group", SENDER_ADDRESS_BOB);

	// Just test from libsignal
	@Test
	public void testBasicEncryptDecrypt() throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException {
		InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
		InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

		GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
		GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

		GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER_ALICE);
		GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER_ALICE);

		SenderKeyDistributionMessage sentAliceDistributionMessage = aliceSessionBuilder.create(GROUP_SENDER_ALICE);
		SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.serialize());
		bobSessionBuilder.process(GROUP_SENDER_ALICE, receivedAliceDistributionMessage);

		byte[] ciphertextFromAlice = aliceGroupCipher.encrypt(Alice_first_message.getBytes());
		byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);

		assertTrue(new String(plaintextFromAlice).equals(Alice_first_message));
	}

	@Test
	public void testGroupOfThree() throws LegacyMessageException, DuplicateMessageException, InvalidMessageException, NoSessionException {

		// Alice initiates secure session for group chat
		InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
		GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
		GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GROUP_SENDER_ALICE);
		SenderKeyDistributionMessage sentAliceDistributionMessage = aliceSessionBuilder.create(GROUP_SENDER_ALICE);

		// this message should be transferred via network for group initiation!
		byte[] initGroupMessage = sentAliceDistributionMessage.serialize();
		// also GROUP_SENDER should be transferred as well

		// meanwhile Alice can start sending messages and do not wait Bob and
		// Medved to init session ( Hm, really? Yes, bro, it seems so...)
		// So she encrypts them and send to the wire....
		byte[] ciphertextFromAlice = aliceGroupCipher.encrypt(Alice_first_message.getBytes());
		byte[] ciphertextFromAlice2 = aliceGroupCipher.encrypt("smert ze smert2".getBytes());

		// bob receives INIT message and initiates the group session:
		SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(initGroupMessage);
		InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();
		GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);
		GroupCipher bobGroupCipher = new GroupCipher(bobStore, GROUP_SENDER_ALICE);
		bobSessionBuilder.process(GROUP_SENDER_ALICE, receivedAliceDistributionMessage);

		// medved receives INIT message and initiates the group session:
		SenderKeyDistributionMessage receivedAliceDistributionMessage2 = new SenderKeyDistributionMessage(initGroupMessage);
		InMemorySenderKeyStore medvedStore = new InMemorySenderKeyStore();
		GroupSessionBuilder medvedSessionBuilder = new GroupSessionBuilder(medvedStore);
		GroupCipher medvedGroupCipher = new GroupCipher(medvedStore, GROUP_SENDER_ALICE);
		medvedSessionBuilder.process(GROUP_SENDER_ALICE, receivedAliceDistributionMessage2);

		// them Bob and MEdved decrypt and read Messages from Alice...
		byte[] plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);
		assertTrue(new String(plaintextFromAlice).equals(Alice_first_message));

		byte[] plaintextFromAlice_to_Medved = medvedGroupCipher.decrypt(ciphertextFromAlice);
		assertTrue(new String(plaintextFromAlice_to_Medved).equals(Alice_first_message));

		byte[] plaintextFromAlice2 = bobGroupCipher.decrypt(ciphertextFromAlice2);
		assertTrue(new String(plaintextFromAlice2).equals(Alice_second_message));

		byte[] plaintextFromAlice_to_Medved2 = medvedGroupCipher.decrypt(ciphertextFromAlice2);
		assertTrue(new String(plaintextFromAlice_to_Medved2).equals(Alice_second_message));

		// And bob decides to answer.
		// He init session for sending messages
		GroupCipher bobGroupCipherReply = new GroupCipher(bobStore, GROUP_SENDER_BOB);

		// this message transmitted to all other participant
		SenderKeyDistributionMessage bobSenderInit = bobSessionBuilder.create(GROUP_SENDER_BOB);

		// Bob encrypt and sent his message
		byte[] cipherReplyFromBob = bobGroupCipherReply.encrypt("Hello this is Bob".getBytes());

		// Medved process init message from Bob
		medvedSessionBuilder.process(GROUP_SENDER_BOB, new SenderKeyDistributionMessage(bobSenderInit.serialize()));
		GroupCipher medvedGroupCipher_from_bob = new GroupCipher(medvedStore, GROUP_SENDER_BOB);

		// Medved can decrypt Bob's message
		byte[] plain = medvedGroupCipher_from_bob.decrypt(cipherReplyFromBob);
		assertTrue(new String(plain).equals("Hello this is Bob"));

		// Alice process init message from Bob
		aliceSessionBuilder.process(GROUP_SENDER_BOB, new SenderKeyDistributionMessage(bobSenderInit.serialize()));
		GroupCipher aliceGroupCipher_from_bob = new GroupCipher(aliceStore, GROUP_SENDER_BOB);
		// Alice can see it too...
		plain = aliceGroupCipher_from_bob.decrypt(cipherReplyFromBob);
		assertTrue(new String(plain).equals("Hello this is Bob"));

		// Alice responds to Bob
		ciphertextFromAlice = aliceGroupCipher.encrypt("Nice to see you here, Bob".getBytes());

		// then Bob and MEdved decrypt and read Messages from Alice...
		plaintextFromAlice = bobGroupCipher.decrypt(ciphertextFromAlice);
		assertTrue(new String(plaintextFromAlice).equals("Nice to see you here, Bob"));

		plaintextFromAlice_to_Medved = medvedGroupCipher.decrypt(ciphertextFromAlice);
		assertTrue(new String(plaintextFromAlice_to_Medved).equals("Nice to see you here, Bob"));

	}

}
