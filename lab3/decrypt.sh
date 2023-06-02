#! /bin/bash

echo fc57c9cfdac7202694e8c2712d1f0e8e21b8c6f6d612d6c96847e42e6257b3f9ea98466cfc8761ed5e0308311deb15 | ./task1 > dat1.b 
echo a83fa0bcfaae5306f5c8b1144e6d6bfa01cca38ea23cf68707258b4a1b77c09185ed2a08dcf5048c3a237c5974983b | ./task1 > dat2.b

len=$(stat -c %s dat1.b)

for (( i=0 ; i < $len ; i++ ))
do
	A=$( od -j $i -N1 -An -t u1 dat1.b)
	B=$( od -j $i -N1 -An -t u1 dat2.b)
	res=$(($A ^ $B))
	ores=$(printf '%o' $res)
	printf \\$ores
done
echo
rm -f dat[12].b
