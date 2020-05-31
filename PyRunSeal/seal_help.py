# coding: utf-8
# author: Huelse
from seal import *


parms = EncryptionParameters(scheme_type.BFV)
poly_modulus_degree = 4096
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
parms.set_plain_modulus(256)
BFV_context = SEALContext.Create(parms)

parms = EncryptionParameters(scheme_type.CKKS)
poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.Create(
    poly_modulus_degree, [40, 40, 40, 40, 40]))
CKKS_context = SEALContext.Create(parms)



