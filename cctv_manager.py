import cv2
import datetime
import os
import threading
from typing import Optional, Dict, List
import time
from models import CCTVCamera, Schedule, DataStore

class CCTVManager:
    def __init__(self, data_store: DataStore, upload_dir: str):
        self.data_store = data_store
        self.upload_dir = upload_dir
        self.active_streams: Dict[str, threading.Thread] = {}
        
    def capture_from_camera(self, camera: CCTVCamera) -> Optional[str]:
        """Capture image from CCTV camera"""
        try:
            # Construct RTSP URL if not provided
            if not camera.rtsp_url:
                url = f"rtsp://{camera.username}:{camera.password}@{camera.ip_address}/stream1"
            else:
                url = camera.rtsp_url

            cap = cv2.VideoCapture(url)
            if not cap.isOpened():
                raise Exception(f"Failed to connect to camera {camera.id}")

            ret, frame = cap.read()
            if not ret:
                raise Exception(f"Failed to capture frame from camera {camera.id}")

            # Save captured frame
            timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"cctv_{camera.id}_{timestamp}.jpg"
            filepath = os.path.join(self.upload_dir, filename)
            cv2.imwrite(filepath, frame)

            return filepath

        except Exception as e:
            print(f"Camera capture error: {str(e)}")
            return None
        finally:
            if 'cap' in locals():
                cap.release()

    def start_monitoring(self, camera_id: str):
        """Start monitoring a specific camera"""
        if camera_id in self.active_streams:
            return False
        
        camera = self.data_store.cameras.get(camera_id)
        if not camera:
            return False

        def monitor():
            while camera_id in self.active_streams:
                filepath = self.capture_from_camera(camera)
                if filepath:
                    print(f"Captured frame from camera {camera_id}")
                time.sleep(1)  # Adjust capture frequency

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        self.active_streams[camera_id] = thread
        return True

    def stop_monitoring(self, camera_id: str):
        """Stop monitoring a specific camera"""
        if camera_id in self.active_streams:
            del self.active_streams[camera_id]
            return True
        return False

    def get_camera_status(self, camera_id: str) -> dict:
        """Get current status of a camera"""
        camera = self.data_store.cameras.get(camera_id)
        if not camera:
            return {'status': 'not_found'}

        is_active = camera_id in self.active_streams
        return {
            'id': camera.id,
            'name': camera.name,
            'status': 'active' if is_active else 'inactive',
            'location': camera.location,
            'floor': camera.floor
        }