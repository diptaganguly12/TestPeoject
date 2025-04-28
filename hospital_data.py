import pandas as pd
import os

class HospitalDataManager:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.csv_path = os.path.join(data_dir, 'hospital_master.csv')
        self.load_data()

    def load_data(self):
        """Load hospital master data from CSV file"""
        if os.path.exists(self.csv_path):
            self.df = pd.read_csv(self.csv_path)
        else:
            self.df = pd.DataFrame(columns=['hospital_name', 'building', 'floor', 'category'])

    def get_hospitals(self):
        """Get list of unique hospital names"""
        return self.df['hospital_name'].unique().tolist()

    def get_buildings(self, hospital_name):
        """Get buildings for a specific hospital"""
        return self.df[self.df['hospital_name'] == hospital_name]['building'].unique().tolist()

    def get_floors(self, hospital_name, building):
        """Get floors for a specific hospital and building"""
        mask = (self.df['hospital_name'] == hospital_name) & (self.df['building'] == building)
        return self.df[mask]['floor'].unique().tolist()

    def get_categories(self, hospital_name, building, floor):
        """Get categories for a specific hospital, building and floor"""
        mask = (
            (self.df['hospital_name'] == hospital_name) & 
            (self.df['building'] == building) & 
            (self.df['floor'] == floor)
        )
        return self.df[mask]['category'].unique().tolist()

    def add_hospital_data(self, hospital_name, building, floor, category):
        """Add new hospital data to CSV"""
        new_data = pd.DataFrame({
            'hospital_name': [hospital_name],
            'building': [building],
            'floor': [floor],
            'category': [category]
        })
        self.df = pd.concat([self.df, new_data], ignore_index=True)
        self.df.to_csv(self.csv_path, index=False)