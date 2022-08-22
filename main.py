from z3 import *
from Crypto.Util.number import *

# threshold = 5, n=???, provided shares = 3, no finite field arithmetics, ~700bit f(x)=y values
# does not provide perfect secrecy = secret value can be deduced with fewer shares
# polynomial of degree 4 = coeff0*x**0 + coeff1*x**1 + coeff2*x**2 + coeff3*x**3 + coeff4*x**4
# coeff0 = flag/secret = we are looking for this value
# all flags in the CTF are in the format of `flag{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}`

threshold = 5
coefficients = [Int(f"coeff{x}") for x in range(threshold)]
# coeff0 as ASCII converted to long integer, limits of
coeff0_limits = [bytes_to_long(b"flag{00000000000000000000000000000000}"),
                 bytes_to_long(b"flag{ffffffffffffffffffffffffffffffff}")]

shares = [
    (2740898742966601935114133183106529,
     956157655799717714864508073016211621761609346753693883071835634336701162346899667843127478623689609421921959757635162027164435651849444039861798305449805669806060897098677034940051454923858123316418111771244842263136200150949),
    (4681515083705154508573047498744706,
     8137729467373933116892508790883965853824225864544185629594304843306928863961691391715058478012421229999432914675335993933647800020626034683613711997688036772875553560302624022039862210798719189229119735618787699810723188634719),
    (713083567420521725647105281913383,
     4380455310144784872605974709167150361708365833979536574950088299593054964905207611091625844071796262320158274849703026573280865132707680730814638177402685313693168998262565678693098484143079216308958193534983606222931969247),
]

# for x, y in shares:
#     print(y, y.bit_length())

s = Solver()

# The coeff0 = secret must he within these limits
s.add(And(coefficients[0] < coeff0_limits[1], coefficients[0] > coeff0_limits[0]))
# coefficients of the polynomial must be > 0
for x in coefficients:
    # print(x)
    s.add(x > 0)

for x, y in shares:
    result = sum([(x ** exponent) * coefficient for exponent, coefficient in enumerate(coefficients)])
    # print(x, y)
    s.add(y == result)

s.check()
model = s.model()
print(model)
converted = long_to_bytes(model[coefficients[0]].as_long())
print(converted)
