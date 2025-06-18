const cloudinary = require('cloudinary').v2;

// Configurar Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Función para subir archivo
const uploadFile = async (buffer, originalName, mimeType) => {
  return new Promise((resolve, reject) => {
    const uploadOptions = {
      resource_type: 'auto',
      public_id: `files/${Date.now()}-${originalName.replace(/[^a-zA-Z0-9.]/g, '_')}`,
      folder: 'file-sharing-app',
      secure: true,
      transformation: [
        { quality: 'auto' },
        { fetch_format: 'auto' }
      ]
    };

    cloudinary.uploader.upload_stream(
      uploadOptions,
      (error, result) => {
        if (error) {
          reject(error);
        } else {
          resolve({
            public_id: result.public_id,
            secure_url: result.secure_url,
            bytes: result.bytes,
            format: result.format
          });
        }
      }
    ).end(buffer);
  });
};

// Función para eliminar archivo
const deleteFile = async (publicId) => {
  try {
    const result = await cloudinary.uploader.destroy(publicId);
    return result;
  } catch (error) {
    console.error('Error eliminando archivo:', error);
    throw error;
  }
};

module.exports = {
  uploadFile,
  deleteFile
};