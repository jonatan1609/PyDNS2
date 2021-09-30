import io
import struct
import typing

from PyDNS2.dns import Header, Question, Response
from socket import socket


def parse(d):
    d = io.BytesIO(d)
    msg_length, = struct.unpack("!H", d.read(2))
    return Response.parse(d.read(msg_length))


def send_request(
        ip,
        header: Header,
        questions: typing.List[Question]
) -> Response:
    assert len(questions) == 1, "Currently we only support one question"
    with socket() as sock:
        sock.connect((ip, 53))
        data = header.write() + b"".join(question.write() for question in questions)
        sock.send(struct.pack("!H", len(data)) + data)
        buffer = sock.recv(1024)
        if len(buffer) == 1024:
            temp_buf = sock.recv(1024)
            while temp_buf:
                buffer += temp_buf
                temp_buf = sock.recv(1024)
    return parse(buffer)
