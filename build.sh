echo "######################################################################"
echo "Construyendo la imagen para ARM64"
echo "######################################################################"
docker build --platform linux/arm64 -t koreadmin/kore-tools:arm64 --target arm64 -f ./Dockerfile .

echo ""
echo "######################################################################"
echo "Construyendo la imagen para AMD64"
echo "######################################################################"
docker build --platform linux/amd64 -t koreadmin/kore-tools:amd64 --target amd64 -f ./Dockerfile .

echo ""
echo "Subiendo las imágenes a Docker Hub..."
docker push koreadmin/kore-tools:arm64
docker push koreadmin/kore-tools:amd64

echo ""
echo "Creando imagen multi-arquitectura..."
docker manifest rm  koreadmin/kore-tools:0.5
docker manifest create koreadmin/kore-tools:0.5 koreadmin/kore-tools:arm64 koreadmin/kore-tools:amd64

echo ""
echo "Subiendo el manifiesto a Docker Hub..."
docker manifest push koreadmin/kore-tools:0.5