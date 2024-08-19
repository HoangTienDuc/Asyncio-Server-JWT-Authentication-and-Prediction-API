import base64
import numpy as np
import cv2
from PIL import Image
from transformers import AutoModel, AutoTokenizer
from common.global_vars import UPLOAD_DIR, Status
import io

def save_image_from_base64(base64_string, filename):
    try:
        # Decode base64 string to bytes
        imgdata = base64.b64decode(base64_string)

        # Convert bytes to numpy array
        nparr = np.frombuffer(imgdata, np.uint8)

        # Decode numpy array to OpenCV image
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        # Save image to file
        cv2.imwrite(str(filename), img)
        return True
    except Exception as e:
        print(f"Error saving image: {e}")
        return False

class LvmHandler:
    def __init__(self):
        """
        Initialize the LvmHandler class.

        This class is responsible for handling image processing and LLM (Large Language Model) inference.
        It loads a pre-trained LLM model and tokenizer, and sets the model to evaluation mode.

        Parameters:
        None

        Returns:
        None
        """
        self.model = AutoModel.from_pretrained('LLM-int4', trust_remote_code=True)
        self.tokenizer = AutoTokenizer.from_pretrained('LLM-int4', trust_remote_code=True)
        self.model.eval()
    
    def predict(self, data, default_question='Is it good?'):
        message_id = data.get('message_id')
        device_id = data.get('device_id')
        camera_id = data.get('camera_id')
        base64_img = data.get('image')
        prompt = data.get('prompt') or default_question
        image = Image.open(io.BytesIO(base64.b64decode(base64_img))).convert('RGB')
        result = self.model.chat(
            image=image,
            msgs=[{'role': 'user', 'content': prompt}],
            tokenizer=self.tokenizer,
            sampling=True,
            temperature=0.7
        )
        return {"status": True, "message": None, "content": result, "message_id": message_id, "device_id": device_id, "camera_id": camera_id, "prompt": prompt}