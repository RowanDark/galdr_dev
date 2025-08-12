import os
import sqlite3
import time
import sys
from PyQt6.QtCore import QCoreApplication
from galdr.core.cve_updater import CVEManager

def verify_cve_updater():
    """
    Tests the CVE updater by running a manual update and checking the database.
    Note: This test performs a live API call to the NVD and may take time.
    """
    print("\n--- Running Test: CVE Updater ---")

    # We need a QCoreApplication for the QTimer/QThread signals to work
    app = QCoreApplication.instance()
    if app is None:
        # sys.argv is required by QCoreApplication
        app = QCoreApplication(sys.argv)

    cve_manager = CVEManager()

    # Clear the database for a clean test
    db_path = "data/cve_database.db"
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Removed existing database at {db_path}")

    # Flag to signal completion
    update_finished = False

    def on_update_complete(stats):
        nonlocal update_finished
        print(f"✅ CVE Update complete signal received: {stats}")
        update_finished = True

    cve_manager.cve_data_updated.connect(on_update_complete)

    print("Starting manual CVE update...")
    if not cve_manager.start_manual_update():
        print("❌ Update was already in progress.")
        return False

    # Wait for the update to finish by processing Qt events
    # This is a more robust way to wait for a QThread to finish in a script
    print("Waiting for CVE update to complete... (This may take a few minutes)")
    start_time = time.time()
    while not update_finished and (time.time() - start_time) < 600: # 10 minute timeout
        app.processEvents()
        time.sleep(0.1)

    if not update_finished:
        print("❌ Test FAILED: Timeout waiting for CVE update to complete.")
        cve_manager.updater_thread.stop()
        return False

    # Verify that the database now contains CVEs
    if not os.path.exists(db_path):
        print(f"❌ Test FAILED: CVE database file was not created at {db_path}.")
        return False

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cves")
        count = cursor.fetchone()[0]

    print(f"Found {count} CVEs in the database.")
    if count > 0:
        print("--- ✅ Test Passed: CVE Updater ---")
        return True
    else:
        print("--- ❌ Test FAILED: No CVEs were added to the database. ---")
        return False

if __name__ == "__main__":
    if verify_cve_updater():
        exit(0)
    else:
        exit(1)
