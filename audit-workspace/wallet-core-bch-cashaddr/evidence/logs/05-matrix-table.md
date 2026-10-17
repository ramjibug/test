| mode | input | payload symbols | exit | result |
|---|---|---|---|---|
| parser | `(empty)` | 0 | 134 | **abort (SIGABRT)** |
| parser | `q` | 1 | 134 | **abort (SIGABRT)** |
| parser | `qq` | 2 | 134 | **abort (SIGABRT)** |
| parser | `qqq` | 3 | 134 | **abort (SIGABRT)** |
| parser | `qqqq` | 4 | 134 | **abort (SIGABRT)** |
| parser | `qqqqq` | 5 | 134 | **abort (SIGABRT)** |
| parser | `qqqqqq` | 6 | 134 | **abort (SIGABRT)** |
| parser | `qqqqqqq` | 7 | 134 | **abort (SIGABRT)** |
| parser | `qqqqqqqq` | 8 | 134 | **abort (SIGABRT)** |
| parser | `qqqqqqqqq` | 9 | 0 | returned normally |
| parser | `qqqqqqqqqq` | 10 | 0 | returned normally |
| parser | `qqqqqqqqqqq` | 11 | 0 | returned normally |
| parser | `qqqqqqqqqqqq` | 12 | 0 | returned normally |
| parser | `qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a` | valid control | 0 | returned normally |
| parser | `bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a` | valid control (prefixed) | 0 | returned normally |
| is_valid | `(empty)` | 0 | 134 | **abort (SIGABRT)** |
| is_valid | `q` | 1 | 134 | **abort (SIGABRT)** |
| is_valid | `qq` | 2 | 134 | **abort (SIGABRT)** |
| is_valid | `qqq` | 3 | 134 | **abort (SIGABRT)** |
| is_valid | `qqqq` | 4 | 134 | **abort (SIGABRT)** |
| is_valid | `qqqqq` | 5 | 134 | **abort (SIGABRT)** |
| is_valid | `qqqqqq` | 6 | 134 | **abort (SIGABRT)** |
| is_valid | `qqqqqqq` | 7 | 134 | **abort (SIGABRT)** |
| is_valid | `qqqqqqqq` | 8 | 134 | **abort (SIGABRT)** |
| is_valid | `qqqqqqqqq` | 9 | 0 | returned normally |
| is_valid | `qqqqqqqqqq` | 10 | 0 | returned normally |
| is_valid | `qqqqqqqqqqq` | 11 | 0 | returned normally |
| is_valid | `qqqqqqqqqqqq` | 12 | 0 | returned normally |
| is_valid | `qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a` | valid control | 0 | returned normally |
| is_valid | `bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a` | valid control (prefixed) | 0 | returned normally |
| with_string | `(empty)` | 0 | 134 | **abort (SIGABRT)** |
| with_string | `q` | 1 | 134 | **abort (SIGABRT)** |
| with_string | `qq` | 2 | 134 | **abort (SIGABRT)** |
| with_string | `qqq` | 3 | 134 | **abort (SIGABRT)** |
| with_string | `qqqq` | 4 | 134 | **abort (SIGABRT)** |
| with_string | `qqqqq` | 5 | 134 | **abort (SIGABRT)** |
| with_string | `qqqqqq` | 6 | 134 | **abort (SIGABRT)** |
| with_string | `qqqqqqq` | 7 | 134 | **abort (SIGABRT)** |
| with_string | `qqqqqqqq` | 8 | 134 | **abort (SIGABRT)** |
| with_string | `qqqqqqqqq` | 9 | 0 | returned normally |
| with_string | `qqqqqqqqqq` | 10 | 0 | returned normally |
| with_string | `qqqqqqqqqqq` | 11 | 0 | returned normally |
| with_string | `qqqqqqqqqqqq` | 12 | 0 | returned normally |
| with_string | `qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a` | valid control | 0 | returned normally |
| with_string | `bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a` | valid control (prefixed) | 0 | returned normally |
| with_string_unchecked | `(empty)` | 0 | 134 | **abort (SIGABRT)** |
| with_string_unchecked | `q` | 1 | 134 | **abort (SIGABRT)** |
| with_string_unchecked | `qq` | 2 | 134 | **abort (SIGABRT)** |
| with_string_unchecked | `qqq` | 3 | 134 | **abort (SIGABRT)** |
| with_string_unchecked | `qqqq` | 4 | 134 | **abort (SIGABRT)** |
| with_string_unchecked | `qqqqq` | 5 | 134 | **abort (SIGABRT)** |
| with_string_unchecked | `qqqqqq` | 6 | 134 | **abort (SIGABRT)** |
| with_string_unchecked | `qqqqqqq` | 7 | 134 | **abort (SIGABRT)** |
| with_string_unchecked | `qqqqqqqq` | 8 | 134 | **abort (SIGABRT)** |
| with_string_unchecked | `qqqqqqqqq` | 9 | 0 | returned normally |
| with_string_unchecked | `qqqqqqqqqq` | 10 | 0 | returned normally |
| with_string_unchecked | `qqqqqqqqqqq` | 11 | 0 | returned normally |
| with_string_unchecked | `qqqqqqqqqqqq` | 12 | 0 | returned normally |
| with_string_unchecked | `qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a` | valid control | 0 | returned normally |
| with_string_unchecked | `bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a` | valid control (prefixed) | 0 | returned normally |
| replay | `crash-0b94ee47...` | fuzz artifact | 134 | **abort (SIGABRT)** |
