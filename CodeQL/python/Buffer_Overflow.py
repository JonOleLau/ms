def maybe_buffer_overflow():
    a = []
    while True:
        a.append('A' * 1000000)

if __name__ == "__main__":
    maybe_buffer_overflow()