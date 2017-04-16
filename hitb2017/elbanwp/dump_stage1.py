with open('stage1.bin', 'w') as f:
    f.write(open('input.bin').read()[0x114+0x1f04:])
