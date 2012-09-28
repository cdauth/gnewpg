cd "$(dirname "$0")"

mkdir build
javac -d build -cp ../node_modules/soynode/soy/SoyToJsSrcCompiler.jar SoyFunctionsModule.java
cd build
jar -cf ../SoyFunctionsModule.jar *
cd ..
rm -rf build
