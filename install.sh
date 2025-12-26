printf "Building hivehunt...\n"
cd hivehunt 
printf "Building dependencies...\n"
go get www.velocidex.com/golang/regparser
go get golang.org/x/text/encoding/charmap
printf "DONE\n"
go build -o ../build/hivehunt main.go
cd ..
printf "hivehunt build complete.\n"

printf "Building lnkinfo...\n"
go build -o build/lnkinfo lnkinfo/main.go
printf "lnkinfo build complete.\n"