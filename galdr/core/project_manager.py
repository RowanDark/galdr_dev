import json
import os
import time
import uuid
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from PyQt6.QtCore import QObject, pyqtSignal

@dataclass
class ScanSettings:
    target_url: str = ""
    depth: int = 2
    headless: bool = True
    delay: float = 1.0
    enable_screenshots: bool = True
    enable_subdomain_enum: bool = False
    enable_passive_scan: bool = True
    use_proxies: bool = False
    region_filter: List[str] = None
    
    def __post_init__(self):
        if self.region_filter is None:
            self.region_filter = []

@dataclass
class UserPreferences:
    theme: str = "dark"
    ai_settings: Dict[str, Any] = None
    proxy_settings: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.ai_settings is None:
            self.ai_settings = {}
        if self.proxy_settings is None:
            self.proxy_settings = {}

@dataclass
class ScanHistoryEntry:
    scan_id: str
    timestamp: float
    results_summary: Dict[str, Any]
    duration: float = 0.0
    status: str = "completed"

@dataclass
class ProjectProfile:
    profile_name: str
    description: str = ""
    created_at: float = 0.0
    last_modified: float = 0.0
    scan_settings: ScanSettings = None
    user_preferences: UserPreferences = None
    scan_history: List[ScanHistoryEntry] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.created_at == 0.0:
            self.created_at = time.time()
        if self.last_modified == 0.0:
            self.last_modified = time.time()
        if self.scan_settings is None:
            self.scan_settings = ScanSettings()
        if self.user_preferences is None:
            self.user_preferences = UserPreferences()
        if self.scan_history is None:
            self.scan_history = []
        if self.tags is None:
            self.tags = []

class ProjectManager(QObject):
    profile_created = pyqtSignal(str)
    profile_loaded = pyqtSignal(str)
    profile_deleted = pyqtSignal(str)
    profile_updated = pyqtSignal(str)
    
    def __init__(self, user_name: str):
        super().__init__()
        self.user_name = user_name
        self.profiles_dir = Path(f"profiles/{user_name}")
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        self.current_profile: Optional[ProjectProfile] = None
        self.profiles_cache: Dict[str, ProjectProfile] = {}
        self.load_all_profiles()
    
    def create_profile(self, profile_name: str, description: str = "", 
                      scan_settings: ScanSettings = None, 
                      user_preferences: UserPreferences = None,
                      tags: List[str] = None) -> bool:
        """Create a new project profile"""
        try:
            if self.profile_exists(profile_name):
                raise ValueError(f"Profile '{profile_name}' already exists")
            
            profile = ProjectProfile(
                profile_name=profile_name,
                description=description,
                scan_settings=scan_settings or ScanSettings(),
                user_preferences=user_preferences or UserPreferences(),
                tags=tags or []
            )
            
            self.save_profile(profile)
            self.profiles_cache[profile_name] = profile
            self.profile_created.emit(profile_name)
            
            return True
        except Exception as e:
            print(f"Error creating profile: {e}")
            return False
    
    def save_profile(self, profile: ProjectProfile) -> bool:
        """Save a profile to disk"""
        try:
            profile.last_modified = time.time()
            profile_path = self.profiles_dir / f"{profile.profile_name}.json"
            
            # Convert to dictionary for JSON serialization
            profile_dict = self.profile_to_dict(profile)
            
            with open(profile_path, 'w') as f:
                json.dump(profile_dict, f, indent=2)
            
            self.profiles_cache[profile.profile_name] = profile
            self.profile_updated.emit(profile.profile_name)
            
            return True
        except Exception as e:
            print(f"Error saving profile: {e}")
            return False
    
    def load_profile(self, profile_name: str) -> Optional[ProjectProfile]:
        """Load a profile from disk"""
        try:
            if profile_name in self.profiles_cache:
                self.current_profile = self.profiles_cache[profile_name]
                self.profile_loaded.emit(profile_name)
                return self.current_profile
            
            profile_path = self.profiles_dir / f"{profile_name}.json"
            if not profile_path.exists():
                return None
            
            with open(profile_path, 'r') as f:
                profile_dict = json.load(f)
            
            profile = self.dict_to_profile(profile_dict)
            self.profiles_cache[profile_name] = profile
            self.current_profile = profile
            self.profile_loaded.emit(profile_name)
            
            return profile
        except Exception as e:
            print(f"Error loading profile: {e}")
            return None
    
    def delete_profile(self, profile_name: str) -> bool:
        """Delete a profile"""
        try:
            profile_path = self.profiles_dir / f"{profile_name}.json"
            if profile_path.exists():
                profile_path.unlink()
            
            if profile_name in self.profiles_cache:
                del self.profiles_cache[profile_name]
            
            if self.current_profile and self.current_profile.profile_name == profile_name:
                self.current_profile = None
            
            self.profile_deleted.emit(profile_name)
            return True
        except Exception as e:
            print(f"Error deleting profile: {e}")
            return False
    
    def list_profiles(self) -> List[str]:
        """Get list of all profile names"""
        return list(self.profiles_cache.keys())
    
    def get_profile_info(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """Get basic info about a profile"""
        if profile_name not in self.profiles_cache:
            return None
        
        profile = self.profiles_cache[profile_name]
        return {
            'name': profile.profile_name,
            'description': profile.description,
            'created_at': profile.created_at,
            'last_modified': profile.last_modified,
            'target_url': profile.scan_settings.target_url,
            'scan_count': len(profile.scan_history),
            'tags': profile.tags
        }
    
    def profile_exists(self, profile_name: str) -> bool:
        """Check if a profile exists"""
        return profile_name in self.profiles_cache
    
    def update_current_profile_settings(self, scan_settings: ScanSettings, 
                                       user_preferences: UserPreferences = None) -> bool:
        """Update current profile with new settings"""
        if not self.current_profile:
            return False
        
        self.current_profile.scan_settings = scan_settings
        if user_preferences:
            self.current_profile.user_preferences = user_preferences
        
        return self.save_profile(self.current_profile)
    
    def add_scan_to_history(self, scan_id: str, results_summary: Dict[str, Any], 
                           duration: float = 0.0, status: str = "completed") -> bool:
        """Add a scan to the current profile's history"""
        if not self.current_profile:
            return False
        
        scan_entry = ScanHistoryEntry(
            scan_id=scan_id,
            timestamp=time.time(),
            results_summary=results_summary,
            duration=duration,
            status=status
        )
        
        self.current_profile.scan_history.append(scan_entry)
        return self.save_profile(self.current_profile)
    
    def export_profile(self, profile_name: str, export_path: str) -> bool:
        """Export a profile to a file"""
        try:
            if profile_name not in self.profiles_cache:
                return False
            
            profile = self.profiles_cache[profile_name]
            profile_dict = self.profile_to_dict(profile)
            
            with open(export_path, 'w') as f:
                json.dump(profile_dict, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error exporting profile: {e}")
            return False
    
    def import_profile(self, import_path: str, new_name: str = None) -> bool:
        """Import a profile from a file"""
        try:
            with open(import_path, 'r') as f:
                profile_dict = json.load(f)
            
            profile = self.dict_to_profile(profile_dict)
            
            if new_name:
                profile.profile_name = new_name
            
            if self.profile_exists(profile.profile_name):
                profile.profile_name = f"{profile.profile_name}_imported_{int(time.time())}"
            
            return self.save_profile(profile)
        except Exception as e:
            print(f"Error importing profile: {e}")
            return False
    
    def load_all_profiles(self):
        """Load all profiles from disk into cache"""
        try:
            for profile_file in self.profiles_dir.glob("*.json"):
                profile_name = profile_file.stem
                try:
                    with open(profile_file, 'r') as f:
                        profile_dict = json.load(f)
                    
                    profile = self.dict_to_profile(profile_dict)
                    self.profiles_cache[profile_name] = profile
                except Exception as e:
                    print(f"Error loading profile {profile_name}: {e}")
        except Exception as e:
            print(f"Error loading profiles: {e}")
    
    def search_profiles(self, query: str) -> List[str]:
        """Search profiles by name, description, or tags"""
        query = query.lower()
        matching_profiles = []
        
        for profile_name, profile in self.profiles_cache.items():
            if (query in profile_name.lower() or 
                query in profile.description.lower() or
                any(query in tag.lower() for tag in profile.tags) or
                query in profile.scan_settings.target_url.lower()):
                matching_profiles.append(profile_name)
        
        return matching_profiles
    
    def get_profiles_by_tag(self, tag: str) -> List[str]:
        """Get profiles that have a specific tag"""
        matching_profiles = []
        for profile_name, profile in self.profiles_cache.items():
            if tag.lower() in [t.lower() for t in profile.tags]:
                matching_profiles.append(profile_name)
        return matching_profiles
    
    def profile_to_dict(self, profile: ProjectProfile) -> Dict[str, Any]:
        """Convert profile to dictionary for JSON serialization"""
        return {
            'profile_name': profile.profile_name,
            'description': profile.description,
            'created_at': profile.created_at,
            'last_modified': profile.last_modified,
            'scan_settings': asdict(profile.scan_settings),
            'user_preferences': asdict(profile.user_preferences),
            'scan_history': [asdict(entry) for entry in profile.scan_history],
            'tags': profile.tags
        }
    
    def dict_to_profile(self, profile_dict: Dict[str, Any]) -> ProjectProfile:
        """Convert dictionary to profile object"""
        scan_settings = ScanSettings(**profile_dict.get('scan_settings', {}))
        user_preferences = UserPreferences(**profile_dict.get('user_preferences', {}))
        
        scan_history = []
        for entry_dict in profile_dict.get('scan_history', []):
            scan_history.append(ScanHistoryEntry(**entry_dict))
        
        return ProjectProfile(
            profile_name=profile_dict['profile_name'],
            description=profile_dict.get('description', ''),
            created_at=profile_dict.get('created_at', time.time()),
            last_modified=profile_dict.get('last_modified', time.time()),
            scan_settings=scan_settings,
            user_preferences=user_preferences,
            scan_history=scan_history,
            tags=profile_dict.get('tags', [])
        )
    
    def get_profile_statistics(self) -> Dict[str, Any]:
        """Get statistics about all profiles"""
        total_profiles = len(self.profiles_cache)
        total_scans = sum(len(profile.scan_history) for profile in self.profiles_cache.values())
        
        # Most used targets
        target_counts = {}
        for profile in self.profiles_cache.values():
            target = profile.scan_settings.target_url
            if target:
                target_counts[target] = target_counts.get(target, 0) + 1
        
        # All tags
        all_tags = set()
        for profile in self.profiles_cache.values():
            all_tags.update(profile.tags)
        
        return {
            'total_profiles': total_profiles,
            'total_scans': total_scans,
            'most_used_targets': sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:5],
            'available_tags': sorted(list(all_tags))
        }
