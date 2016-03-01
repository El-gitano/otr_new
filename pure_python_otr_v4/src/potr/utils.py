# -*-coding:Utf-8 -*
#    Copyright 2012 Kjell Braden <afflux@pentabarf.de>
#
#    This file is part of the python-potr library.
#
#    python-potr is free software; you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation; either version 3 of the License, or
#    any later version.
#
#    python-potr is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with this library.  If not, see <http://www.gnu.org/licenses/>.

# some python3 compatibilty
from __future__ import unicode_literals
import struct

# Stocke un nombre sous forme packée
def pack_mpi(n):
    return pack_data(long_to_bytes(n))

# Lit un nombre et retourne un tuple (nombre, reste_des_donnees)
def read_mpi(data):
    n, data = read_data(data)
    return bytes_to_long(n), data

# Stocke des données sous la forme (taille_donnees | donnees)
def pack_data(data):
    return struct.pack(b'!I', len(data)) + data

# Lire des données packées sous le format (taille_donnees | donnees)
# Retourne les données
def read_data(data):
    datalen, data = unpack(b'!I', data)
    return data[:datalen], data[datalen:]
    
def unpack(fmt, buf):
    s = struct.Struct(fmt)
    return s.unpack(buf[:s.size]) + (buf[s.size:],)

# Transforme une suite d'octets en un entier
def bytes_to_long(b):
    l = len(b)
    s = 0
    for i in range(l):
        s += byte_to_long(b[i:i+1]) << 8*(l-i-1)
    return s

# n definit le nombre d'octets sur lequel on souhaite stocker le long
# l correspond à l'entier à encoder
def long_to_bytes(l, n=0):
    b = b''
    while l != 0 or n > 0:
        b = long_to_byte(l & 0xff) + b
        l >>= 8
        n -= 1
    return b

# Transforme un octet en entier
def byte_to_long(b):
    return struct.unpack(b'B', b)[0]

# Transforme un entier en une suite  d'octets
def long_to_byte(l):
    return struct.pack(b'B', l)

def human_hash(fp):
    fp = fp.upper()
    fplen = len(fp)
    wordsize = fplen//5
    buf = ''
    for w in range(0, fplen, wordsize):
        buf += '{0} '.format(fp[w:w+wordsize])
    return buf.rstrip()
