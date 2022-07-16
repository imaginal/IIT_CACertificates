#!/usr/bin/env python
from pyasn1.type import univ, tag, namedtype
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1_modules import rfc2315
from glob import glob
import sys


class MyExtendedCertificatesAndCertificates(univ.SetOf):
    componentType = rfc2315.Certificate()


class MySignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', rfc2315.Version()),
        namedtype.NamedType('digestAlgorithms', univ.Any()),
        namedtype.NamedType('contentInfo', rfc2315.ContentInfo()),
        namedtype.NamedType('certificates', MyExtendedCertificatesAndCertificates().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('crls', univ.Any())
    )


def main():
    if len(sys.argv) < 3:
        print("usage: {} dir-with-certs output.p7b".format(*sys.argv))
        return

    substrate = open('empty.p7b', 'rb').read()
    ci, _ = der_decoder.decode(substrate, asn1Spec=rfc2315.ContentInfo())
    si, _ = der_decoder.decode(ci['content'], asn1Spec=MySignedData())
    si['certificates'].clear()

    for fn in glob(sys.argv[1]+'/*.crt'):
        print("Read", fn)
        cer = open(fn, 'rb').read()
        cerObj, _ = der_decoder.decode(cer, asn1Spec=rfc2315.Certificate())
        si['certificates'].append(cerObj)

    if len(si['certificates']) == 0:
        print("No *.crt found")
        return

    ci['content'] = si

    substrate = der_encoder.encode(ci)
    print("Write", sys.argv[2])
    with open(sys.argv[2], 'wb') as fp:
        fp.write(substrate)

    print("OK")


if __name__ == '__main__':
    main()
