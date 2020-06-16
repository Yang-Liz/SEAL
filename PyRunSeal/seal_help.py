# coding: utf-8
# author: Huelse
from seal import *


parms = EncryptionParameters(scheme_type.BFV)
poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.BFVDefault(poly_modulus_degree))
parms.set_plain_modulus(256)
BFV_context = SEALContext.Create(parms)

parms = EncryptionParameters(scheme_type.CKKS)
poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(CoeffModulus.Create(
    poly_modulus_degree, [60, 40, 40, 60]))
CKKS_context = SEALContext.Create(parms)



def ckks_mul(x_encrypted, y_encrypted, relin_keys, context):  # x_encrypted,y_encrypted是明文x，y对应的密文类，返回x*y对应的密文类
    evaluator = Evaluator(context)
    x_encrypted.scale(pow(2.0, 40))
    y_encrypted.scale(pow(2.0, 40))
    a = int(context.get_context_data(x_encrypted.parms_id()).chain_index())
    b = int(context.get_context_data(y_encrypted.parms_id()).chain_index())
    if(a < b):
        last_parms_id = x_encrypted.parms_id()
        evaluator.mod_switch_to_inplace(y_encrypted, last_parms_id)
    else:
        last_parms_id = y_encrypted.parms_id()
        evaluator.mod_switch_to_inplace(x_encrypted, last_parms_id)
    mul_encrypted = Ciphertext()
    evaluator.multiply(x_encrypted, y_encrypted, mul_encrypted)
    evaluator.relinearize_inplace(mul_encrypted, relin_keys)
    evaluator.rescale_to_next_inplace(mul_encrypted)
    return mul_encrypted



