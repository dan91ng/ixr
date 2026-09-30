#!/usr/bin/env python3
import os
import sys


def main():
    command = '/usr/local/bin/ixr-apply'
    os.execv(command, [command, *sys.argv[1:]])


if __name__ == '__main__':
    main()
