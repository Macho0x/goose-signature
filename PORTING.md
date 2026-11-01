# Porting

`solana::begin` takes `Message.Legacy` or `Message.V0`. A cast is checked unless a mask already put the byte in range. The digit in an EIP-191 length stays unchecked because division by 10 produced it.
