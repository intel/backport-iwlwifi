#ifndef __BP_ASYMMETRIC_TYPE_H
#define __BP_ASYMMETRIC_TYPE_H

int x509_load_certificate_list(const u8 cert_list[], const unsigned long list_size,
			       const struct key *keyring);

#endif /* _KEYS_ASYMMETRIC_TYPE_H */