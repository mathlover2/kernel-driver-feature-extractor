from collections import Counter
from math import log2

def entropy(data):
    if data:
        entropy = 0
        line = data
        total = len(line)
        chars_dict = Counter(line) # This replaces a whole block of
                                   # Perl code explicitly splitting
                                   # the line and implementing the
                                   # counter directly
        distincts = len(chars_dict)
        for key in chars_dict:
            p = chars_dict[key]/total
            entropy += p*log2(p+1) # The original Perl code used the
                                   # base change rule with the natural
                                   # logarithm. We just use log2 here.
        entropy /= distincts
        return entropy
    else:
        return 10

def none_english_extractor(data):
    r"""Counts the number of non-alphanumeric ASCII characters in the
source.

    """
    line = data
    n_e = 0
    for char in line:
        if char not in ascii_letters and char not in digits:
            n_e += 1
    return n_e
            
