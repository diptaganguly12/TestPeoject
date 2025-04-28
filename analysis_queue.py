from dataclasses import dataclass
from typing import Optional
import threading
from queue import Queue, Empty
import time
from datetime import datetime
import json
import os
import schedule  # Need to install this package: pip install schedule

@dataclass
class AnalysisTask:
    id: str
    filename: str
    metadata: dict
    status: str
    created_at: str
    priority: bool = False  # New field for priority
    completed_at: Optional[str] = None
    analysis_results: Optional[dict] = None
    error: Optional[str] = None

class AnalysisQueue:
    def __init__(self, upload_folder, analyze_func):
        self.queue = Queue()
        self.priority_queue = Queue()  # New queue for priority tasks
        self.tasks = {}
        self.processing_thread = None
        self.scheduler_thread = None
        self.is_running = False
        self.processing_enabled = False  # Flag to control when processing is allowed
        self.upload_folder = upload_folder
        self.analyze_func = analyze_func
        self.task_lock = threading.Lock()  # Added missing task_lock for thread safety
        self.observers = []  # For implementing the observer pattern

    def start(self):
        if not self.is_running:
            self.is_running = True
            
            # Set up the scheduler to enable processing at 9 PM
            schedule.every().day.at("21:00").do(self._enable_processing)
            
            # Start the scheduler thread
            self.scheduler_thread = threading.Thread(target=self._run_scheduler)
            self.scheduler_thread.daemon = True
            self.scheduler_thread.start()
            
            # Start the processing thread
            self.processing_thread = threading.Thread(target=self._process_queue)
            self.processing_thread.daemon = True
            self.processing_thread.start()
            
            print("Analysis queue started. Regular processing will begin at 9 PM.")

    def stop(self):
        self.is_running = False
        if self.processing_thread:
            self.processing_thread.join(timeout=2)
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=2)

    def add_task(self, filename: str, metadata: dict, priority: bool = False, run_immediately: bool = False) -> str:
        """Add a task to the analysis queue
        
        Args:
            filename: The filename of the image to analyze
            metadata: Metadata associated with the image
            priority: If True, the task will be processed ahead of regular tasks
            run_immediately: If True, the task will be processed immediately
            
        Returns:
            The task ID
        """
        task_id = f"task_{int(time.time())}_{filename}"
        task = AnalysisTask(
            id=task_id,
            filename=filename,
            metadata=metadata,
            status="pending",
            priority=priority,
            created_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        with self.task_lock:
            self.tasks[task_id] = task
            
            if run_immediately:
                # Process the task immediately in a separate thread
                process_thread = threading.Thread(target=self._process_task, args=(task_id,))
                process_thread.daemon = True
                process_thread.start()
                print(f"Processing task {task_id} immediately")
            elif priority:
                self.priority_queue.put(task_id)
                print(f"Added priority task {task_id} to queue")
            else:
                self.queue.put(task_id)
                print(f"Added regular task {task_id} to queue (will process after 9 PM)")
                
        # Notify observers about the new task
        self._notify_observers()
            
        return task_id

    def set_task_priority(self, task_id: str, priority: bool = True, run_immediately: bool = False) -> bool:
        """Update the priority of an existing task
        
        Args:
            task_id: The ID of the task
            priority: If True, the task will be processed ahead of regular tasks
            run_immediately: If True, the task will be processed immediately
            
        Returns:
            True if the priority was updated, False otherwise
        """
        with self.task_lock:
            if task_id not in self.tasks:
                return False
                
            task = self.tasks[task_id]
            
            # Only change priority if the task is still pending
            if task.status == "pending":
                task.priority = priority
                
                # Process immediately if requested
                if run_immediately and priority:
                    # Process the task immediately in a separate thread
                    process_thread = threading.Thread(target=self._process_task, args=(task_id,))
                    process_thread.daemon = True
                    process_thread.start()
                    print(f"Processing task {task_id} immediately")
                elif priority:
                    # Need to remove from regular queue and add to priority queue
                    # Note: This is inefficient as Queue doesn't support removal
                    # A better implementation would use a different queue implementation
                    self.priority_queue.put(task_id)
                    print(f"Task {task_id} priority set to high")
                
                # Notify observers about the change
                self._notify_observers()
                return True
            return False

    def get_task(self, task_id: str) -> Optional[AnalysisTask]:
        """Get a task by ID"""
        return self.tasks.get(task_id)

    def _enable_processing(self):
        """Enable processing of the regular queue"""
        self.processing_enabled = True
        print("Processing enabled at scheduled time (9 PM)")
        # Notify observers about the change
        self._notify_observers()
        return schedule.CancelJob  # Run once then reschedule for tomorrow

    def _run_scheduler(self):
        """Run the scheduler in a separate thread"""
        while self.is_running:
            schedule.run_pending()
            time.sleep(60)  # Check every minute

    def _process_queue(self):
        """Process queued tasks in a background thread"""
        while self.is_running:
            try:
                # Always process priority queue regardless of time
                if not self.priority_queue.empty():
                    task_id = self.priority_queue.get(timeout=1)
                    self._process_task(task_id)
                    continue
                
                # Only process regular queue if processing is enabled (after 9 PM)
                if self.processing_enabled and not self.queue.empty():
                    task_id = self.queue.get(timeout=1)
                    self._process_task(task_id)
                    
                    # If queue is empty, disable processing until next scheduled time
                    if self.queue.empty():
                        self.processing_enabled = False
                        print("Regular queue empty, disabling processing until next scheduled time")
                        # Notify observers about the change
                        self._notify_observers()
                else:
                    # Sleep to avoid busy waiting
                    time.sleep(1)
                    
            except Empty:
                # No tasks to process, wait a bit
                time.sleep(1)
            except Exception as e:
                print(f"Critical error in queue processing: {str(e)}")
                time.sleep(5)  # Wait a bit longer after an error
                continue

    def cancel_task(self, task_id):
        """Cancel a pending task by its ID"""
        with self.task_lock:
            if task_id not in self.tasks:
                return False
            
            task = self.tasks[task_id]
            if task.status != 'pending':
                # Can only cancel pending tasks
                return False
            
            # Remove the task from the queue (if it's still there)
            # We need to remove from both priority and regular queue
            # Note: This is slower but safer than trying to figure out which queue it's in
            
            # Create temporary lists to hold tasks we want to keep
            priority_tasks = []
            regular_tasks = []
            
            # Empty the priority queue and keep everything except our task
            while not self.priority_queue.empty():
                queued_task_id = self.priority_queue.get()
                if queued_task_id != task_id:
                    priority_tasks.append(queued_task_id)
            
            # Put all the kept tasks back
            for kept_task_id in priority_tasks:
                self.priority_queue.put(kept_task_id)
            
            # Do the same for regular queue
            while not self.queue.empty():
                queued_task_id = self.queue.get()
                if queued_task_id != task_id:
                    regular_tasks.append(queued_task_id)
            
            # Put all the kept tasks back
            for kept_task_id in regular_tasks:
                self.queue.put(kept_task_id)
            
            # Update the task status
            task.status = 'cancelled'
            self._update_task_status(task_id, 'cancelled')
            
            # Notify observers about the change
            self._notify_observers()
            
            return True

    def _update_task_status(self, task_id, status, error=None):
        """Update the status of a task
        
        Args:
            task_id: The ID of the task
            status: The new status
            error: Optional error message
        """
        with self.task_lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                task.status = status
                if error:
                    task.error = error
                task.completed_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                
                # Notify observers about the change
                self._notify_observers()

    def _process_task(self, task_id):
        """Process a single task by ID"""
        if task_id not in self.tasks:
            print(f"Task {task_id} not found in tasks dictionary")
            return
            
        with self.task_lock:
            task = self.tasks[task_id]
            task.status = "processing"
            # Notify observers about the change
            self._notify_observers()
        
        try:
            # Get the full path of the image
            image_path = os.path.join(self.upload_folder, task.filename)
            metadata_path = os.path.join(self.upload_folder, f"{task.filename}.json")
            
            # Verify files exist
            if not os.path.exists(image_path):
                raise FileNotFoundError(f"Image file not found: {image_path}")
            
            if not os.path.exists(metadata_path):
                raise FileNotFoundError(f"Metadata file not found: {metadata_path}")
            
            # Read existing metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Store the original fields we want to preserve
            preserved_fields = {
                'filename': task.filename,
                'hospital_name': metadata.get('hospital_name', 'Unknown'),
                'building': metadata.get('building', 'Unknown'),
                'floor': metadata.get('floor', 'Unknown'),
                'category': metadata.get('category', 'Unknown'),
                'location': metadata.get('location', 'Unknown'),
                'timestamp': metadata.get('timestamp'),
                'geolocation': metadata.get('geolocation'),
                'task_id': task_id,
                'priority': task.priority,
                'uploaded_by': metadata.get('uploaded_by', 'diptaganguly12')
            }
            
            # Perform image analysis
            results = self.analyze_func(image_path)
            
            if results:
                task.analysis_results = results
                task.status = "completed"
                
                # Create new metadata with preserved fields and analysis results
                updated_metadata = {
                    **preserved_fields,
                    'status': 'completed',
                    'analysis_results': results,
                    'comment': results.get('comment', 'No comment available'),
                    'created_at': metadata.get('created_at'),
                    'completed_at': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                }
            else:
                raise Exception("Analysis produced no results")
            
        except FileNotFoundError as e:
            task.status = "failed"
            task.error = str(e)
            print(f"File error in task {task_id}: {str(e)}")
            updated_metadata = {
                **preserved_fields,
                'status': 'failed',
                'error': f"File error: {str(e)}",
                'completed_at': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            }
            
        except Exception as e:
            task.status = "failed"
            task.error = str(e)
            print(f"Error processing task {task_id}: {str(e)}")
            updated_metadata = {
                **preserved_fields,
                'status': 'failed',
                'error': str(e),
                'completed_at': datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            }
        
        finally:
            # Always try to update the metadata file
            try:
                if 'metadata_path' in locals() and 'updated_metadata' in locals():
                    with open(metadata_path, 'w') as f:
                        json.dump(updated_metadata, f, indent=2)
            except Exception as write_error:
                print(f"Error updating metadata file: {str(write_error)}")
            
            with self.task_lock:
                if task_id in self.tasks:
                    task = self.tasks[task_id]
                    task.completed_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                    # Notify observers about the change
                    self._notify_observers()
            
            # Mark task as done in appropriate queue if it was in a queue
            # This might throw an exception if the task wasn't in a queue, so we catch it
            try:
                if getattr(task, 'priority', False):
                    self.priority_queue.task_done()
                else:
                    self.queue.task_done()
            except Exception:
                pass

    # Observer pattern implementation
    def register_observer(self, observer):
        """Register an observer to be notified of queue changes"""
        if observer not in self.observers:
            self.observers.append(observer)
            
    def unregister_observer(self, observer):
        """Unregister an observer"""
        if observer in self.observers:
            self.observers.remove(observer)
            
    def _notify_observers(self):
        """Notify all observers of a change in the queue"""
        for observer in self.observers:
            try:
                observer(self)
            except Exception as e:
                print(f"Error notifying observer: {str(e)}")
                
    def get_pending_tasks(self):
        """Get all pending tasks for serialization and persistence"""
        pending_tasks = []
        with self.task_lock:
            for task_id, task in self.tasks.items():
                if task.status == 'pending':
                    pending_tasks.append({
                        'task_id': task_id,
                        'filename': task.filename,
                        'priority': task.priority,
                        'created_at': task.created_at,
                        'metadata': task.metadata
                    })
        return pending_tasks