""" common.py """


def linecount(filename):
    """calculate the total number of lines in the file really quickly

    :param filename:

    """
    with open(filename, "rb") as open_f:
        lines = 0
        buf_size = 1024 * 1024
        read_f = open_f.raw.read
        buf = read_f(buf_size)
        while buf:
            lines += buf.count(b"\n")
            buf = read_f(buf_size)
    open_f.close()
    return lines
