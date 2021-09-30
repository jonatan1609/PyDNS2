import struct
import typing
import io
from BitFieldArray import BitFieldArray
from secrets import randbits


class Resources:
    class IP:
        TYPE_VALUE = 1
        TYPE = "A"

        def __init__(self, ip, n_octets, class_: int = 1):
            self._ip = ip
            self.n_octets = n_octets
            self.resource_class = class_

        @property
        def ip(self) -> str:
            return ".".join(map(str, self._ip))

        @property
        def ip_as_int(self) -> int:
            return BitFieldArray(8, 8, 8, 8).assign(self._ip).export()

        @property
        def ip_as_tuple(self):
            return self._ip

        @classmethod
        def parse(cls, d: bytes):
            ip = struct.unpack("!" + "B" * len(d), d)
            return cls(
                ip=ip,
                n_octets=len(ip),

            )

    resources = {
        IP.TYPE_VALUE: IP
    }


class Header:
    def __init__(
            self,
            entries: int,
            pkt_id: int = None,
            bit_field: int = 256,
    ):
        self.bitfield = BitFieldArray(1, 4, 1, 1, 1, 1, 3, 4).from_int(bit_field)
        assert self.bitfield[-2].value == 0, "Z must be set to zero in all queries and responses."
        self.entries = entries
        self.id = pkt_id or randbits(16)
        self.qd_count = entries
        self.an_count = 0
        self.ns_count = 0
        self.ar_count = 0

    def write(self):
        return struct.pack(
            "!HHHHHH",
            self.id,
            self.bitfield.export(),
            self.qd_count,
            self.an_count,
            self.ns_count,
            self.ar_count
        )

    @classmethod
    def read(cls, pkt_id: int, flags: int):
        header = cls(0, pkt_id, flags)
        return header


class Question:
    def __init__(self, name: str):
        self.qname = self.make_labels(name)
        self.q_type = struct.pack("!H", 1)
        self.q_class = self.q_type

    @staticmethod
    def make_labels(name) -> bytearray:
        array = bytearray()
        tree = name.split(".")
        for node in tree:
            array.append(len(node))
            array.extend([ord(x) for x in node])
        array.append(0)
        return array

    def write(self):
        return self.qname + self.q_type + self.q_class

    @classmethod
    def read(cls, name: str, q_type: int, q_class: int):
        question = cls(name)
        question.q_type = q_type
        question.q_class = q_class
        return question


class Response:
    def __init__(
            self,
            header: Header,
            questions: typing.List[Question],
            name: str,
            ttl: int,
            resources: typing.List[
                Resources.IP
            ]
    ):
        self.header = header
        self.questions = questions
        self.domain_name = name
        self.ttl = ttl
        self.resources = resources

    @staticmethod
    def build_labels(d: io.BytesIO) -> str:
        length = struct.unpack("B", d.read(1))[0]
        tree = []
        while length != 0x00:
            tree.append(d.read(length))
            length = struct.unpack("B", d.read(1))[0]
        return b".".join(tree).decode()

    @staticmethod
    def parse(d: bytes):
        d = io.BytesIO(d)
        pkt_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", d.read(12))
        name = Response.build_labels(d)
        q_type, q_class, pointer, type_, _, ttl, rd_length = struct.unpack("!HHHHHIH", d.read(16))
        if (pointer >> 14) & 0x3 == 0x3:
            offset = pointer & (1 << 14) - 1
            name = Response.build_labels(io.BytesIO(d.getvalue()[offset:]))
        resource = Resources.resources[type_].parse(d.read(rd_length))
        return Response(
            header=Header.read(pkt_id, flags),
            questions=[Question.read(name, q_type, q_class)],  # currently only one question/resource is supported
            name=name,
            ttl=ttl,
            resources=[resource]
        )
