def add_semicolon(str):
    if len(str.strip()) == 0 or str.strip()[-1] in ["{", "(", ","]:
        return str
    
    idx = str.find("//")
    if idx != -1:
        comment = str[idx:]
        str = str[0:idx]
        return add_semicolon(str) + comment
    
    if str.find("\n") != -1:
        return str.replace("\n", ";\n")
    return str + ";"



f = open("d_orig.txt", "r")

lines = f.readlines()
f2 = open("d_new.txt", "w")

for i in range(len(lines)):
    lines[i] = add_semicolon(lines[i])

f2.writelines(lines)

f.close()
f2.close()
