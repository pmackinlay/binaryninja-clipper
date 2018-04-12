
def unpack(input_data):
    input_index = 0
    output_data = ''

    # initialise the ring buffer
    ring_buffer = [' ' if x < 0xfee else '\0' for x in range(4096)]
    ring_index = 0xfee

    control_byte = 0
    while input_index < len(input_data):
        control_byte = control_byte >> 1

        if control_byte & 0x100 == 0:
            control_byte = ord(input_data[input_index]) | 0xff00
            input_index += 1

        if control_byte & 0x1:
            # output byte unchanged
            byte = input_data[input_index]
            input_index += 1

            output_data += byte

            ring_buffer[ring_index] = byte
            ring_index = (ring_index + 1) & 0xfff
        else:
            # get two input bytes
            byte1 = ord(input_data[input_index])
            input_index += 1
            byte2 = ord(input_data[input_index])
            input_index += 1

            # 'x' bits become index into ring buffer
            # 'y' bits set length of output sequence (+3)
            #
            # xxxx xxxx xxxx yyyy

            index = (byte1) | ((byte2 & 0xf0) << 4)
            count = (byte2 & 0xf) + 3

            for i in range(count):
                ring_byte = ring_buffer[(index + i) & 0xfff]

                output_data += ring_byte

                ring_buffer[ring_index] = ring_byte
                ring_index = (ring_index + 1) & 0xfff

    return output_data
