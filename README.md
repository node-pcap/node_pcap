node_pcap
=========

This is not done yet.  If you want to see how awesome it will be, check this out:

Run the test program as root to be able to open the capture device:

    mjr:~/work/node_pcap$ sudo node test.js

Here is the "API":

    DEBUG: { findalldevs: [Function]
    , open_live: [Function]
    , dispatch: [Function]
    , fileno: [Function]
    , close: [Function]
    , stats: [Function]
    }

Output from `findalldevs`:

    open_live starting en0
    [ { name: 'en0'
      , addresses: 
         [ { addr: '10.51.2.183'
           , netmask: '255.255.255.0'
           , broadaddr: '10.51.2.255'
           }
         ]
      }
    , { name: 'fw0', addresses: [] }
    , { name: 'en1', addresses: [] }
    , { name: 'lo0'
      , addresses: [ { addr: '127.0.0.1', netmask: '255.0.0.0' } ]
      , flags: 'PCAP_IF_LOOPBACK'
      }
    ]

114 bytes of actual packet, one byte at a time, not in any way decoded:

    DEBUG: readWatcher callback
    packet no: 1, 1274297591.327988, length: 114
    DEBUG: callback called back.
    Header:
    { time: Wed, 19 May 2010 19:33:11 GMT
    , caplen: 114
    , len: 114
    }
    Packet:
    0: 0
    1: 30
    2: 201
    3: 69
    4: 232
    5: 48
    6: 0
    7: 23
    8: 242
    9: 15
    10: 73
    11: 166
    12: 8
    13: 0
    14: 69
    15: 16
    16: 0
    17: 100
    18: 79
    19: 217
    20: 64
    21: 0
    22: 64
    23: 6
    24: 0
    25: 0
    26: 10
    27: 51
    28: 2
    29: 183
    30: 184
    31: 72
    32: 56
    33: 14
    34: 194
    35: 128
    36: 0
    37: 22
    38: 35
    39: 18
    40: 29
    41: 237
    42: 204
    43: 198
    44: 127
    45: 66
    46: 128
    47: 24
    48: 255
    49: 255
    50: 253
    51: 150
    52: 0
    53: 0
    54: 1
    55: 1
    56: 8
    57: 10
    58: 30
    59: 53
    60: 251
    61: 183
    62: 25
    63: 167
    64: 111
    65: 129
    66: 79
    67: 239
    68: 209
    69: 172
    70: 31
    71: 174
    72: 86
    73: 55
    74: 64
    75: 127
    76: 107
    77: 87
    78: 148
    79: 233
    80: 9
    81: 97
    82: 107
    83: 118
    84: 181
    85: 185
    86: 21
    87: 17
    88: 164
    89: 241
    90: 194
    91: 137
    92: 91
    93: 224
    94: 66
    95: 149
    96: 22
    97: 194
    98: 205
    99: 229
    100: 234
    101: 98
    102: 117
    103: 198
    104: 136
    105: 205
    106: 181
    107: 146
    108: 223
    109: 34
    110: 214
    111: 15
    112: 246
    113: 132
    
Output from `pcap_stats`:
    
    { ps_recv: 17, ps_drop: 0, ps_ifdrop: 1606411320 }

