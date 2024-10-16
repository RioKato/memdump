def create_segm(start_ea: int, protection: str, name: str, data: bytes):
    from ida_segment import segment_t, saRelByte, add_segm_ex, ADDSEG_OR_DIE, SEGPERM_READ, SEGPERM_WRITE, SEGPERM_EXEC
    from ida_bytes import patch_bytes

    perm = 0

    if 'r' in protection:
        perm |= SEGPERM_READ
    if 'w' in protection:
        perm |= SEGPERM_WRITE
    if 'x' in protection:
        perm |= SEGPERM_EXEC

    segment = segment_t()
    segment.start_ea = start_ea
    segment.end_ea = start_ea + len(data)
    segment.perm = perm
    segment.bitness = 2  # 64bit segment
    segment.align = saRelByte
    add_segm_ex(segment, name, None, ADDSEG_OR_DIE)
    patch_bytes(start_ea, data)


def load_modules():
    from contextlib import suppress
    from json import load

    with open('modules.json') as fd:
        modules = load(fd)

    for m in modules:
        base = m['base']
        base = int(base, 16)
        protection = m['protection']
        file = f'{base:x}.bin'

        start_ea = base
        name = ''

        if 'file' in m:
            name = m['file']['path']

        with suppress(FileNotFoundError):
            with open(file, 'rb') as fp:
                data = fp.read()
                create_segm(start_ea, protection, name, data)


def instpat(ea: int) -> int:
    from idc import generate_disasm_line, GENDSM_FORCE_CODE

    line = generate_disasm_line(ea, GENDSM_FORCE_CODE)
    return True


def add_xrefs():
    from idc import BADADDR, next_head, add_dref, dr_R

    ea = 0
    while ea < BADADDR:
        if xref := instpat(ea):
            add_dref(ea, xref, dr_R)  # (R)ead

        ea = next_head(ea)


def main():
    load_modules()
    add_xrefs()


if __name__ == '__main__':
    main()
