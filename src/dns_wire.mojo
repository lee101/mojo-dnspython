"""DNS wire-format kernels and their C ABI."""

from std.algorithm import sync_parallelize
from std.sys.info import simd_width_of

comptime BPtr = UnsafePointer[UInt8, AnyOrigin[mut=True]]
comptime IPtr = UnsafePointer[Int64, AnyOrigin[mut=True]]
comptime W = simd_width_of[DType.float64]()
comptime PARALLEL_DECODE_THRESHOLD = 4096
comptime DECODE_CHUNK_SIZE = 1024


def _u16(buf: BPtr, pos: Int) -> Int:
    return (Int(buf[pos]) << 8) | Int(buf[pos + 1])


def _u32(buf: BPtr, pos: Int) -> Int:
    return (
        (Int(buf[pos]) << 24)
        | (Int(buf[pos + 1]) << 16)
        | (Int(buf[pos + 2]) << 8)
        | Int(buf[pos + 3])
    )


def _copy_bytes(src: BPtr, dst: BPtr, count: Int):
    var vector_end = count - count % W
    var i = 0
    while i < vector_end:
        var values = src.load[width=W](i)
        dst.store(i, values)
        i += W
    while i < count:
        dst[i] = src[i]
        i += 1


def _decode_name(
    message: BPtr,
    message_len: Int,
    current: Int,
    dst: BPtr,
    capacity: Int,
    write_output: Bool,
    result: IPtr,
):
    """Decode one compressed name.

    result is [status, bytes_consumed, expanded_wire_length]. Status values are
    0 success, 1 truncated/form error, 2 bad pointer, 3 bad label type, and
    4 name too long.
    """
    result[0] = 1
    result[1] = 0
    result[2] = 0
    if current < 0 or current >= message_len:
        return

    var pos = current
    var biggest_pointer = current
    var furthest = current
    var expanded = 0
    while True:
        if pos >= message_len:
            return
        var count = Int(message[pos])
        pos += 1
        if pos > furthest:
            furthest = pos

        if count == 0:
            if expanded + 1 > 255 or expanded + 1 > capacity:
                result[0] = 4
                return
            if write_output:
                dst[expanded] = UInt8(0)
            expanded += 1
            result[0] = 0
            result[1] = Int64(furthest - current)
            result[2] = Int64(expanded)
            return
        elif count < 64:
            if pos + count > message_len:
                return
            if expanded + count + 1 > 255 or expanded + count + 1 > capacity:
                result[0] = 4
                return
            if write_output:
                dst[expanded] = UInt8(count)
                _copy_bytes(message + pos, dst + expanded + 1, count)
            expanded += count + 1
            pos += count
            if pos > furthest:
                furthest = pos
        elif count >= 192:
            if pos >= message_len:
                return
            var target = ((count & 63) << 8) | Int(message[pos])
            pos += 1
            if pos > furthest:
                furthest = pos
            if target >= biggest_pointer:
                result[0] = 2
                return
            biggest_pointer = target
            pos = target
        else:
            result[0] = 3
            return


@export("mdns_name_decode")
def mdns_name_decode(
    message_addr: Int,
    message_len: Int,
    current: Int,
    dst_addr: Int,
    capacity: Int,
    result_addr: Int,
) abi("C"):
    if result_addr == 0:
        return
    var result = IPtr(unsafe_from_address=result_addr)
    result[0] = 1
    result[1] = 0
    result[2] = 0
    if message_addr == 0 or dst_addr == 0 or message_len <= 0 or capacity <= 0:
        return
    _decode_name(
        BPtr(unsafe_from_address=message_addr),
        message_len,
        current,
        BPtr(unsafe_from_address=dst_addr),
        capacity,
        True,
        IPtr(unsafe_from_address=result_addr),
    )


@export("mdns_names_decode")
def mdns_names_decode(
    message_addr: Int,
    message_len: Int,
    offsets_addr: Int,
    count: Int,
    dst_addr: Int,
    stride: Int,
    results_addr: Int,
) abi("C"):
    if count <= 0 or results_addr == 0:
        return
    var results = IPtr(unsafe_from_address=results_addr)
    for i in range(count):
        results[i * 3] = 1
        results[i * 3 + 1] = 0
        results[i * 3 + 2] = 0
    if message_len <= 0 or stride <= 0:
        return
    if (
        message_addr == 0
        or offsets_addr == 0
        or dst_addr == 0
    ):
        return
    var message = BPtr(unsafe_from_address=message_addr)
    var offsets = IPtr(unsafe_from_address=offsets_addr)
    var dst = BPtr(unsafe_from_address=dst_addr)

    def decode_one(i: Int) capturing:
        _decode_name(
            message,
            message_len,
            Int(offsets[i]),
            dst + i * stride,
            stride,
            True,
            results + i * 3,
        )

    if count < PARALLEL_DECODE_THRESHOLD:
        for i in range(count):
            decode_one(i)
    else:
        var chunk_count = (count + DECODE_CHUNK_SIZE - 1) // DECODE_CHUNK_SIZE

        def decode_chunk(chunk: Int) raises capturing:
            var start = chunk * DECODE_CHUNK_SIZE
            var stop = min(start + DECODE_CHUNK_SIZE, count)
            for i in range(start, stop):
                _decode_name(
                    message,
                    message_len,
                    Int(offsets[i]),
                    dst + i * stride,
                    stride,
                    True,
                    results + i * 3,
                )

        sync_parallelize[decode_chunk](chunk_count)


@export("mdns_name_encode")
def mdns_name_encode(
    src_addr: Int,
    src_len: Int,
    dst_addr: Int,
    dst_capacity: Int,
    canonicalize: Int,
    result_addr: Int,
) abi("C"):
    """Validate and encode an uncompressed label sequence."""
    if result_addr == 0:
        return
    var result = IPtr(unsafe_from_address=result_addr)
    result[0] = 1
    result[1] = 0
    if (
        src_addr == 0
        or dst_addr == 0
        or dst_capacity < src_len
        or dst_capacity < 0
    ):
        return
    var src = BPtr(unsafe_from_address=src_addr)
    var dst = BPtr(unsafe_from_address=dst_addr)
    if src_len < 1 or src_len > 255:
        result[0] = 4
        return
    var pos = 0
    while True:
        if pos >= src_len:
            return
        var count = Int(src[pos])
        if count >= 64:
            result[0] = 3
            return
        dst[pos] = src[pos]
        pos += 1
        if pos + count > src_len:
            return
        for j in range(count):
            var value = src[pos + j]
            if canonicalize != 0 and value >= UInt8(65) and value <= UInt8(90):
                value += UInt8(32)
            dst[pos + j] = value
        pos += count
        if count == 0:
            if pos != src_len:
                return
            result[0] = 0
            result[1] = Int64(pos)
            return


@export("mdns_scan_message")
def mdns_scan_message(
    message_addr: Int,
    message_len: Int,
    rows_addr: Int,
    capacity: Int,
    ignore_trailing: Int,
    result_addr: Int,
) abi("C"):
    """Scan question and RR envelopes into rows of eight Int64 values."""
    if result_addr == 0:
        return
    var result = IPtr(unsafe_from_address=result_addr)
    result[0] = 1
    result[1] = 0
    result[2] = 0
    if message_addr == 0 or message_len < 12 or capacity < 0:
        return
    if rows_addr == 0:
        return
    var message = BPtr(unsafe_from_address=message_addr)
    var rows = IPtr(unsafe_from_address=rows_addr)

    var counts0 = _u16(message, 4)
    var counts1 = _u16(message, 6)
    var counts2 = _u16(message, 8)
    var counts3 = _u16(message, 10)
    var total = counts0 + counts1 + counts2 + counts3
    if total > capacity:
        result[0] = 5
        return

    var scratch = IPtr(unsafe_from_address=result_addr) + 3
    var pos = 12
    var row = 0
    for section in range(4):
        var section_count = counts0
        if section == 1:
            section_count = counts1
        elif section == 2:
            section_count = counts2
        elif section == 3:
            section_count = counts3
        for _ in range(section_count):
            var start = pos
            _decode_name(message, message_len, pos, message, 255, False, scratch)
            if scratch[0] != 0:
                result[0] = scratch[0]
                result[1] = Int64(row)
                result[2] = Int64(pos)
                return
            var consumed = Int(scratch[1])
            pos += consumed
            var base = row * 8
            rows[base] = Int64(section)
            rows[base + 1] = Int64(start)
            rows[base + 2] = Int64(consumed)
            if section == 0:
                if pos + 4 > message_len:
                    return
                rows[base + 3] = Int64(_u16(message, pos))
                rows[base + 4] = Int64(_u16(message, pos + 2))
                rows[base + 5] = Int64(-1)
                rows[base + 6] = Int64(-1)
                rows[base + 7] = Int64(0)
                pos += 4
            else:
                if pos + 10 > message_len:
                    return
                var rdlength = _u16(message, pos + 8)
                if pos + 10 + rdlength > message_len:
                    return
                rows[base + 3] = Int64(_u16(message, pos))
                rows[base + 4] = Int64(_u16(message, pos + 2))
                rows[base + 5] = Int64(_u32(message, pos + 4))
                rows[base + 6] = Int64(pos + 10)
                rows[base + 7] = Int64(rdlength)
                pos += 10 + rdlength
            row += 1

    if ignore_trailing == 0 and pos != message_len:
        result[0] = 6
        result[1] = Int64(row)
        result[2] = Int64(pos)
        return
    result[0] = 0
    result[1] = Int64(row)
    result[2] = Int64(pos)
