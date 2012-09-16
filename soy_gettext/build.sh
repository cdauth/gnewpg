cd "$(dirname "$0")"

mkdir build
javac -d build -cp ../node_modules/soynode/soy/SoyToJsSrcCompiler.jar SoyGettextModule.java
cd build
jar -cf ../SoyGettextModule.jar *
cd ..
rm -rf build
