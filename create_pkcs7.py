#!/usr/bin/env python
from pyasn1.type import univ, tag, namedtype
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1_modules import rfc2315
from base64 import b64decode
import sys

EMPTY_P7B = 'MCUGCSqGSIb3DQEHAqAYMBYCAQExADALBgkqhkiG9w0BBwGgADEA'


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


def do_append(p7bfile, cerfiles, clear=False):
    try:
        substrate = open(p7bfile, 'rb').read()
    except FileNotFoundError:
        substrate = b64decode(EMPTY_P7B)

    ci, _ = der_decoder.decode(substrate, asn1Spec=rfc2315.ContentInfo())
    si, _ = der_decoder.decode(ci['content'], asn1Spec=MySignedData())
    if clear:
        si['certificates'].clear()

    for fn in cerfiles:
        print("Read", fn)
        cer = open(fn, 'rb').read()
        cerObj, _ = der_decoder.decode(cer, asn1Spec=rfc2315.Certificate())
        si['certificates'].append(cerObj)

    ci['content'] = si

    substrate = der_encoder.encode(ci)
    print("Write", p7bfile)
    with open(p7bfile, 'wb') as fp:
        fp.write(substrate)

    print("OK")


def do_extract(p7bfile):
    substrate = open(p7bfile, 'rb').read()
    ci, _ = der_decoder.decode(substrate, asn1Spec=rfc2315.ContentInfo())
    si, _ = der_decoder.decode(ci['content'], asn1Spec=MySignedData())

    for cer in si['certificates']:
        substrate = der_encoder.encode(cer)
        serialNumber = cer['tbsCertificate']['serialNumber']
        cerfile = "CA-{:X}.cer".format(int(serialNumber))
        print("Write", cerfile)
        with open(cerfile, 'wb') as fp:
            fp.write(substrate)


def do_delete(p7bfile):
    return do_append(p7bfile, [], True)


def do_test(p7bfile, verbose=False):
    substrate = open(p7bfile, 'rb').read()
    ci, _ = der_decoder.decode(substrate, asn1Spec=rfc2315.ContentInfo())
    si, _ = der_decoder.decode(ci['content'], asn1Spec=MySignedData())

    for cer in si['certificates']:
        if verbose:
            print(cer['tbsCertificate'].prettyPrint())
        else:
            print_cert(cer['tbsCertificate'])


def decode_subject(asn1subj):
    subject = []
    for rdn in asn1subj[0]:
        for nv in rdn:
            try:
                value = nv['value']._value
                value = value[2:].decode('utf8')
            except UnicodeDecodeError:
                value = str(nv['value'])
            subject.append(value)
    return "; ".join(subject)


def print_cert(cer):
    print("")
    print("{:10}: {:X}".format("Serial", int(cer['serialNumber'])))
    print("{:10}: {}".format("Algorithm", cer['signature']['algorithm']))
    issuer = decode_subject(cer['issuer'])
    print("{:10}: {}".format("Issuer", issuer))
    subject = decode_subject(cer['subject'])
    print("{:10}: {}".format("Subject", subject))
    notBefore = cer['validity']['notBefore']['utcTime'].asDateTime
    notAfter = cer['validity']['notAfter']['utcTime'].asDateTime
    print("{:10}: {} - {}".format("Validity", notBefore, notAfter))
    print("")


def main():
    if len(sys.argv) < 3:
        print("Usage:", sys.argv[0], "[c|a|x|d|t] file.p7b file.cer ...")
        print("c - create\na - append\nx - extract\nd - delete\nt - test")
        return

    cmd = sys.argv[1]

    if cmd == 'c':
        return do_append(sys.argv[2], sys.argv[3:], True)
    if cmd == 'a':
        return do_append(sys.argv[2], sys.argv[3:], False)
    elif cmd == 'x':
        return do_extract(sys.argv[2])
    elif cmd == 'd':
        return do_delete(sys.argv[2])
    elif cmd == 't':
        return do_test(sys.argv[2], False)
    elif cmd == 'v':
        return do_test(sys.argv[2], True)
    else:
        print("Unknown command:", cmd)
        return


if __name__ == '__main__':
    main()
