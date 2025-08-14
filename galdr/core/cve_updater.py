import json
import time
import logging
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
from PyQt6.QtCore import QObject, pyqtSignal, QTimer, QThread
import sqlite3

@dataclass
class CVEEntry:
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    published_date: str
    modified_date: str
    affected_products: List[str]
    references: List[str]
    exploit_available: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class CVEDatabase:
    def __init__(self, db_path: str = "data/cve_database.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        self.init_database()
    
    def init_database(self):
        """Initialize CVE database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS cves (
                        cve_id TEXT PRIMARY KEY,
                        description TEXT,
                        cvss_score REAL,
                        severity TEXT,
                        published_date TEXT,
                        modified_date TEXT,
                        affected_products TEXT,
                        references TEXT,
                        exploit_available INTEGER,
                        last_updated INTEGER
                    )
                """)
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS technology_cve_mapping (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        technology TEXT,
                        version_pattern TEXT,
                        cve_id TEXT,
                        FOREIGN KEY (cve_id) REFERENCES cves (cve_id)
                    )
                """)
                
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_tech_cve ON technology_cve_mapping (technology, cve_id)
                """)
                
                conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to initialize CVE database: {e}")
    
    def store_cve(self, cve: CVEEntry) -> bool:
        """Store CVE in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO cves 
                    (cve_id, description, cvss_score, severity, published_date, modified_date, 
                     affected_products, references, exploit_available, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    cve.cve_id,
                    cve.description,
                    cve.cvss_score,
                    cve.severity,
                    cve.published_date,
                    cve.modified_date,
                    json.dumps(cve.affected_products),
                    json.dumps(cve.references),
                    int(cve.exploit_available),
                    int(time.time())
                ))
                conn.commit()
                return True
        except Exception as e:
            self.logger.error(f"Failed to store CVE {cve.cve_id}: {e}")
            return False
    
    def get_cves_for_technology(self, technology: str, version: str = None) -> List[CVEEntry]:
        """Get CVEs for a specific technology"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if version:
                    # More sophisticated version matching would go here
                    cursor.execute("""
                        SELECT c.* FROM cves c
                        JOIN technology_cve_mapping m ON c.cve_id = m.cve_id
                        WHERE m.technology = ? AND c.affected_products LIKE ?
                    """, (technology.lower(), f'%{version}%'))
                else:
                    cursor.execute("""
                        SELECT c.* FROM cves c
                        JOIN technology_cve_mapping m ON c.cve_id = m.cve_id
                        WHERE m.technology = ?
                    """, (technology.lower(),))
                
                cves = []
                for row in cursor.fetchall():
                    cve = CVEEntry(
                        cve_id=row[0],
                        description=row[1],
                        cvss_score=row[2],
                        severity=row[3],
                        published_date=row[4],
                        modified_date=row[5],
                        affected_products=json.loads(row[6]) if row[6] else [],
                        references=json.loads(row[7]) if row[7] else [],
                        exploit_available=bool(row[8])
                    )
                    cves.append(cve)
                
                return cves
        except Exception as e:
            self.logger.error(f"Failed to get CVEs for {technology}: {e}")
            return []
    
    def get_database_stats(self) -> Dict[str, int]:
        """Get database statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) FROM cves")
                total_cves = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(DISTINCT technology) FROM technology_cve_mapping")
                technologies_covered = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM cves WHERE exploit_available = 1")
                exploitable_cves = cursor.fetchone()[0]
                
                return {
                    'total_cves': total_cves,
                    'technologies_covered': technologies_covered,
                    'exploitable_cves': exploitable_cves
                }
        except Exception as e:
            self.logger.error(f"Failed to get database stats: {e}")
            return {'total_cves': 0, 'technologies_covered': 0, 'exploitable_cves': 0}

class CVEUpdaterThread(QThread):
    update_progress = pyqtSignal(str, int)  # message, percentage
    update_complete = pyqtSignal(dict)  # statistics
    update_error = pyqtSignal(str)  # error message
    
    def __init__(self):
        super().__init__()
        self.cve_db = CVEDatabase()
        self.logger = logging.getLogger(__name__)
        self.should_stop = False
    
    def run(self):
        """Run CVE update process"""
        try:
            asyncio.run(self.update_cve_database())
        except Exception as e:
            self.update_error.emit(f"CVE update failed: {str(e)}")
    
    async def update_cve_database(self):
        """Update CVE database from multiple sources"""
        self.update_progress.emit("Starting CVE database update...", 0)
        
        # The order is important: get all CVEs from MITRE first, then enrich with exploit data.
        sources = [
            self.update_from_mitre,
            self.update_from_exploit_db
        ]
        
        total_sources = len(sources)
        updated_cves = 0
        
        for i, source_func in enumerate(sources):
            if self.should_stop:
                break
                
            try:
                count = await source_func()
                updated_cves += count
                progress = int(((i + 1) / total_sources) * 100)
                self.update_progress.emit(f"Updated {count} CVEs from source {i+1}", progress)
            except Exception as e:
                self.logger.error(f"Failed to update from source {i+1}: {e}")
        
        # Update technology mappings
        if not self.should_stop:
            self.update_progress.emit("Updating technology mappings...", 95)
            await self.update_technology_mappings()
        
        stats = self.cve_db.get_database_stats()
        stats['newly_updated'] = updated_cves
        
        self.update_complete.emit(stats)
    
    async def update_from_nvd(self) -> int:
        """This is now a placeholder, as the MITRE source is more comprehensive."""
        self.logger.info("Skipping NVD update; using MITRE CVE List as the primary source.")
        await asyncio.sleep(0) # Yield control
        return 0

    async def update_from_mitre(self) -> int:
        """
        Updates the CVE database by cloning or pulling the cvelistV5 repository
        from GitHub and parsing the JSON files.
        """
        CVE_REPO_URL = "https://github.com/CVEProject/cvelistV5.git"
        # Store the repo in a subdirectory of the data folder
        repo_path = self.cve_db.db_path.parent / "cvelistV5"
        total_cves_updated = 0

        try:
            # 1. Clone or pull the repository
            if repo_path.exists():
                self.logger.info(f"Updating existing CVE repository at {repo_path}...")
                # Using os.system for simplicity in this context
                os.system(f"cd {repo_path} && git pull")
            else:
                self.logger.info(f"Cloning CVE repository to {repo_path}...")
                os.system(f"git clone --depth 1 {CVE_REPO_URL} {repo_path}")

            # 2. Walk the directory and parse JSON files
            cve_dir = repo_path / "cves"
            self.logger.info(f"Starting to parse CVE JSON files from {cve_dir}...")

            for root, dirs, files in os.walk(cve_dir):
                if self.should_stop:
                    self.logger.info("CVE update from MITRE stopped by user.")
                    break

                for file in files:
                    if file.endswith(".json"):
                        file_path = Path(root) / file
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                cve_data = json.load(f)

                            cve_id = cve_data.get('cveMetadata', {}).get('cveId')
                            if not cve_id:
                                continue

                            # Extract data from CVE JSON 5.0 format
                            containers = cve_data.get('containers', {}).get('cna', {})

                            description = "No description."
                            for desc_item in containers.get('descriptions', []):
                                if desc_item.get('lang') == 'en':
                                    description = desc_item.get('value', description)
                                    break

                            cvss_score = 0.0
                            severity = "UNKNOWN"
                            metrics = containers.get('metrics', [])
                            if metrics:
                                # Find the most relevant CVSS score (prefer v3.1)
                                cvss_data = metrics[0].get('cvssV3_1', metrics[0].get('cvssV3_0', {}))
                                if cvss_data:
                                    cvss_score = cvss_data.get('baseScore', 0.0)
                                    severity = cvss_data.get('baseSeverity', "UNKNOWN")

                            published_date = cve_data.get('cveMetadata', {}).get('datePublished')
                            modified_date = cve_data.get('cveMetadata', {}).get('dateUpdated')
                            references = [ref.get('url') for ref in containers.get('references', [])]

                            # This source doesn't have exploit data, so we keep the default
                            exploit_available = False

                            cve = CVEEntry(
                                cve_id=cve_id,
                                description=description,
                                cvss_score=cvss_score,
                                severity=severity,
                                published_date=published_date,
                                modified_date=modified_date,
                                affected_products=[], # Parsing affected products is complex, placeholder for now
                                references=references,
                                exploit_available=exploit_available
                            )

                            if self.cve_db.store_cve(cve):
                                total_cves_updated += 1

                        except json.JSONDecodeError:
                            self.logger.warning(f"Could not parse JSON file: {file_path}")
                        except Exception as e:
                            self.logger.error(f"Error processing file {file_path}: {e}")

            self.logger.info(f"Finished parsing. Updated/added {total_cves_updated} CVEs from MITRE.")

        except Exception as e:
            self.logger.error(f"An error occurred during the MITRE CVE update process: {e}")

        return total_cves_updated
    
    async def update_from_exploit_db(self) -> int:
        """
        Updates the exploit_available flag in the CVE database by cloning or
        pulling the exploit-db repository and parsing its index file.
        """
        EXPLOITDB_REPO_URL = "https://github.com/offensive-security/exploitdb.git"
        repo_path = self.cve_db.db_path.parent / "exploitdb"
        total_exploits_mapped = 0

        try:
            # 1. Clone or pull the repository
            if repo_path.exists():
                self.logger.info(f"Updating existing Exploit-DB repository at {repo_path}...")
                os.system(f"cd {repo_path} && git pull")
            else:
                self.logger.info(f"Cloning Exploit-DB repository to {repo_path}...")
                os.system(f"git clone --depth 1 {EXPLOITDB_REPO_URL} {repo_path}")

            # 2. Parse the CSV file
            csv_path = repo_path / "files_exploits.csv"
            self.logger.info(f"Parsing Exploit-DB index file from {csv_path}...")

            if not csv_path.exists():
                self.logger.error("Could not find files_exploits.csv in the Exploit-DB repository.")
                return 0

            with open(csv_path, 'r', encoding='utf-8') as f:
                # The CSV has a header, which we can skip
                next(f)
                for line in f:
                    if self.should_stop:
                        self.logger.info("Exploit-DB update stopped by user.")
                        break

                    try:
                        # This file is not standard CSV, but we can parse it manually
                        parts = line.strip().split(',')
                        if len(parts) < 4: continue

                        codes = parts[3] # The 'codes' column contains CVE IDs
                        if 'CVE-' in codes:
                            # A single entry can have multiple CVEs, separated by ';'
                            cve_ids = [code.strip() for code in codes.split(';') if 'CVE-' in code]
                            for cve_id in cve_ids:
                                # Update the exploit_available flag in our database
                                with sqlite3.connect(self.cve_db.db_path) as conn:
                                    cursor = conn.cursor()
                                    cursor.execute(
                                        "UPDATE cves SET exploit_available = 1 WHERE cve_id = ?",
                                        (cve_id,)
                                    )
                                    if cursor.rowcount > 0:
                                        total_exploits_mapped += 1
                    except Exception:
                        continue # Skip malformed lines

            self.logger.info(f"Finished mapping exploits. Mapped {total_exploits_mapped} exploits to CVEs.")

        except Exception as e:
            self.logger.error(f"An error occurred during the Exploit-DB update process: {e}")

        return total_exploits_mapped
    
    async def update_technology_mappings(self):
        """Update technology to CVE mappings"""
        # This would analyze CVE descriptions and map them to technologies
        try:
            with sqlite3.connect(self.cve_db.db_path) as conn:
                cursor = conn.cursor()
                
                # Sample mappings
                mappings = [
                    ("nginx", "nginx.*", "CVE-2024-0001"),
                    ("wordpress", "wordpress.*", "CVE-2024-0002"),
                ]
                
                for tech, pattern, cve_id in mappings:
                    cursor.execute("""
                        INSERT OR IGNORE INTO technology_cve_mapping 
                        (technology, version_pattern, cve_id) VALUES (?, ?, ?)
                    """, (tech, pattern, cve_id))
                
                conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to update technology mappings: {e}")
    
    def stop(self):
        """Stop the update process"""
        self.should_stop = True

class CVEManager(QObject):
    cve_data_updated = pyqtSignal(dict)  # New CVE statistics
    vulnerability_alert = pyqtSignal(str, list)  # technology, list of critical CVEs
    
    def __init__(self):
        super().__init__()
        self.cve_db = CVEDatabase()
        self.logger = logging.getLogger(__name__)
        
        # Auto-update timer (daily)
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.start_auto_update)
        self.update_timer.start(24 * 60 * 60 * 1000)  # 24 hours
        
        self.updater_thread = None
    
    def start_manual_update(self):
        """Start manual CVE database update"""
        if self.updater_thread and self.updater_thread.isRunning():
            return False
        
        self.updater_thread = CVEUpdaterThread()
        self.updater_thread.update_progress.connect(self.on_update_progress)
        self.updater_thread.update_complete.connect(self.on_update_complete)
        self.updater_thread.update_error.connect(self.on_update_error)
        self.updater_thread.start()
        
        return True
    
    def start_auto_update(self):
        """Start automatic CVE database update"""
        self.logger.info("Starting automatic CVE database update")
        self.start_manual_update()
    
    def on_update_progress(self, message: str, percentage: int):
        """Handle update progress"""
        self.logger.info(f"CVE Update: {message} ({percentage}%)")
    
    def on_update_complete(self, stats: dict):
        """Handle update completion"""
        self.logger.info(f"CVE update completed: {stats}")
        self.cve_data_updated.emit(stats)
    
    def on_update_error(self, error_message: str):
        """Handle update error"""
        self.logger.error(f"CVE update error: {error_message}")
    
    def check_technology_vulnerabilities(self, technology: str, version: str = None) -> List[CVEEntry]:
        """Check for vulnerabilities in a specific technology"""
        cves = self.cve_db.get_cves_for_technology(technology, version)
        
        # Check for critical vulnerabilities and emit alert
        critical_cves = [cve for cve in cves if cve.cvss_score >= 9.0]
        if critical_cves:
            self.vulnerability_alert.emit(technology, critical_cves)
        
        return cves
    
    def get_vulnerability_summary(self, technologies: Dict[str, Dict]) -> Dict[str, Any]:
        """Get vulnerability summary for detected technologies"""
        summary = {
            'total_vulnerabilities': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'exploitable_count': 0,
            'technology_risks': {}
        }
        
        for tech_name, tech_info in technologies.items():
            version = tech_info.get('version', '')
            cves = self.check_technology_vulnerabilities(tech_name, version)
            
            if cves:
                tech_risk = {
                    'total_cves': len(cves),
                    'critical': len([c for c in cves if c.cvss_score >= 9.0]),
                    'high': len([c for c in cves if 7.0 <= c.cvss_score < 9.0]),
                    'medium': len([c for c in cves if 4.0 <= c.cvss_score < 7.0]),
                    'low': len([c for c in cves if c.cvss_score < 4.0]),
                    'exploitable': len([c for c in cves if c.exploit_available]),
                    'cves': [cve.to_dict() for cve in cves[:5]]  # Top 5 CVEs
                }
                
                summary['technology_risks'][tech_name] = tech_risk
                summary['total_vulnerabilities'] += len(cves)
                summary['critical_count'] += tech_risk['critical']
                summary['high_count'] += tech_risk['high']
                summary['medium_count'] += tech_risk['medium']
                summary['low_count'] += tech_risk['low']
                summary['exploitable_count'] += tech_risk['exploitable']
        
        return summary
    
    def get_database_info(self) -> Dict[str, Any]:
        """Get CVE database information"""
        stats = self.cve_db.get_database_stats()
        
        # Add last update time
        try:
            with sqlite3.connect(self.cve_db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT MAX(last_updated) FROM cves")
                last_update = cursor.fetchone()[0]
                stats['last_updated'] = last_update if last_update else 0
        except:
            stats['last_updated'] = 0
        
        return stats
