const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

// Tailles d'icônes requises par le manifest
const sizes = [16, 32, 72, 96, 128, 144, 152, 192, 384, 512];

async function generateIcons() {
  const svgPath = path.join(__dirname, 'icons', 'icon-512x512.svg');
  const iconsDir = path.join(__dirname, 'icons');
  
  // Vérifier que le fichier SVG existe
  if (!fs.existsSync(svgPath)) {
    console.error('Fichier SVG source non trouvé:', svgPath);
    return;
  }
  
  console.log('Génération des icônes PNG (normales et -v2)...');
  
  for (const size of sizes) {
    const outputPath = path.join(iconsDir, `icon-${size}x${size}.png`);
    const outputPathV2 = path.join(iconsDir, `icon-${size}x${size}-v2.png`);
    try {
      await sharp(svgPath)
        .resize(size, size)
        .png()
        .toFile(outputPath);
      await sharp(svgPath)
        .resize(size, size)
        .png()
        .toFile(outputPathV2);
      console.log(`✓ Icônes ${size}x${size} générées: ${outputPath}, ${outputPathV2}`);
    } catch (error) {
      console.error(`✗ Erreur lors de la génération de l'icône ${size}x${size}:`, error.message);
    }
  }
  
  console.log('Génération terminée !');
}

generateIcons().catch(console.error); 