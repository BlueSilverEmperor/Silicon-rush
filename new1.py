s=input("Enter String: ")
p=s.split()
for i in range(len(s)):    
    if i%2==0:
        t=p[i+1]
        p[i+1]=p[i]
        p[i]=t
    else:
        continue

print(p)