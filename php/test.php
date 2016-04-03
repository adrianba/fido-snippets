<?php
include('fido-authenticator.php');

$challenge = 'Y2xpbWIgYSBtb3VudGFpbg';

$pk = '{ 	"kty" : "RSA", 	"alg" : "RS256", 	"ext" : false, 	"n" : "k-d_ZbVlAu-EBhRNlevnd0cBqJEPlhBefOMMLgHeGTS28Uev6_xHVCZ774I2XdtVF-M5En0aTdekAX82K2SVnO9TEZ4GdJFR1kW1jppLtrlUyjQqggq60OwkUxHM14XDQBhvgeW3fjpETraB-R_scyGeK7lNWMF8jW-NjvU_nljTyuHoDVnYJxPuCunlQ7uzg80iURp0jFKhw7FedPkzyQllG0HRRfzwQG1WOyECxkdPmMk7iPdF-B-Z78S9Fd8Dx2R8OZHEpFMdQ3Z3bMLG8prSbXcmBXlBtmwSLPzEEb3FuPdJQtXzVyg2i3jAR25zWA_XemXHBv7XE5Mf3JYldQ", 	"e" : "AQAB" }';

$d = 'ew0KCSJjaGFsbGVuZ2UiIDogIlkyeHBiV0lnWVNCdGIzVnVkR0ZwYmciLA0KCSJ1c2VyUHJvbXB0IiA6ICJIZWxsbyEiDQp9AA';

$s = 'M-GT64y3FXoFQI8fRPq8ogckxuVYqv65R2eJEXGpbmVtm3Zn9Oa6ik4nClFMsN4h42e9bSBslMTEKW-J1oAoxF8n4JkDH82b9j4bFhhSRMHCbmE-uZm1RX8zVrGIgoWnXDy2nGQSu5xN-BhGubru1x0sXo9ZAdXKc-5hkp6SfIdXAY15o9flsag_H_CpIJ1_L1-vO5K8xhya_iOezflNlqa8-D1lI-xMJ7dOqyPwqg33ryW4l6iTtexuiYhZaGOOyJ5ZxzchjKrw9zMgQOsjbsrM7Q6bu7K7YvOoULxM5WJFdCLj0OBZznrskEHlLrSe0TSr_WrY1SkLhRaUCetKkg';

$a = 'AQAAAAA';

$v = fido_authenticator::validate_signature($pk,$d,$a,$s,$challenge) ? 'verified' : 'unverified';
print("Result -> $v\n");
?>