taocrypt=$(./test.exe)
let es=$?
echo "$taocrypt"

if [ $es -ne 0 ]; then
    echo "taocrypt test failed with exit status $es"
fi

