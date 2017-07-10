 def PolligHellman(P,Q):
    zList = list()
    conjList = list()
    rootList = list()
    n = P.order()
    factorList = n.factor()
    for facTuple in factorList:
    P0 = (ZZ(n/facTuple[0]))*P
    conjList.append(0)
    rootList.append(facTuple[0]^facTuple[1])
    for i in range(facTuple[1]):
    Qpart = Q
    for j in range(1,i+1):
    Qpart = Qpart - (zList[j-1]*(facTuple[0]^(j-1))*P)
    Qi = (ZZ(n/(facTuple[0]^(i+1))))*Qpart
    zList.insert(i,discrete_log(Qi,P0,operation='+'))
    conjList[-1] = conjList[-1] + zList[i]*(facTuple[0]^i)
    return crt(conjList,rootList)
    E = EllipticCurve(GF(7919), [234,75])
    P = E.gens()[0]
    Q = 2341*P
    PolligHellman(P,Q)
