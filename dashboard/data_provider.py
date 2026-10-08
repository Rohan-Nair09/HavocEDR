import logging
from typing import List, Dict, Any
from sqlalchemy import desc, asc
from sqlalchemy.orm import Session
from database.connection import SessionLocal
from database.models import Alert, Report, ProcessEvent, ServiceEvent, NetworkConnection, USBEvent, FileEvent, RegistryEvent, SysmonEvent

logger = logging.getLogger(__name__)

class DataProvider:
    """
    Single database access layer for all UI pages.
    Handles querying, sorting, filtering, and pagination.
    """
    
    # Model mapping for dynamic queries
    MODEL_MAP = {
        "alerts": Alert,
        "processes": ProcessEvent,
        "services": ServiceEvent,
        "network": NetworkConnection,
        "usb": USBEvent,
        "file": FileEvent,
        "registry": RegistryEvent,
        "sysmon": SysmonEvent,
        "reports": Report,
    }

    @staticmethod
    def get_kpis() -> Dict[str, int]:
        """Fetch high-level KPIs for the Overview page."""
        db = SessionLocal()
        try:
            kpis = {
                "total_alerts": db.query(Alert).count(),
                "critical_alerts": db.query(Alert).filter(Alert.severity == "Critical").count(),
                "open_alerts": db.query(Alert).filter(Alert.status == "Open").count(),
                "processes": db.query(ProcessEvent).count(),
                "services": db.query(ServiceEvent).count(),
                "network": db.query(NetworkConnection).count(),
                "usb": db.query(USBEvent).count(),
                "file": db.query(FileEvent).count(),
                "registry": db.query(RegistryEvent).count(),
                "sysmon": db.query(SysmonEvent).count(),
                "resolved_alerts": db.query(Alert).filter(Alert.status == "Resolved").count(),
                "active_alerts": db.query(Alert).filter(Alert.status.in_(["Open", "Investigating"])).count(),
                "reports": db.query(Report).count(),
            }
            kpis["total_events"] = sum(kpis[key] for key in ("processes", "services", "network", "usb", "file", "registry", "sysmon"))
            return kpis
        except Exception as e:
            logger.error(f"Failed to fetch KPIs: {e}")
            return {}
        finally:
            db.close()

    @staticmethod
    def fetch_data(table_name: str, limit: int = 100, offset: int = 0, 
                   sort_col: str = "id", sort_desc: bool = True,
                   filters: Dict[str, Any] = None,
                   include_total: bool = True) -> tuple[List[Any], int | None]:
        """
        Generic fetch method for pagination, filtering, and sorting.
        Returns a tuple of (results_list, total_count).
        """
        if table_name not in DataProvider.MODEL_MAP:
            raise ValueError(f"Unknown table: {table_name}")
            
        model = DataProvider.MODEL_MAP[table_name]
        db = SessionLocal()
        
        try:
            query = db.query(model)
            
            # Apply exact match filters
            if filters:
                for k, v in filters.items():
                    if hasattr(model, k) and v is not None and v != "":
                        query = query.filter(getattr(model, k) == v)
            
            # Large telemetry tables can contain millions of snapshots. Views
            # that only display the newest page should skip a full-table COUNT.
            total_count = query.count() if include_total else None
            
            # Apply sorting
            if hasattr(model, sort_col):
                col_attr = getattr(model, sort_col)
                if sort_desc:
                    query = query.order_by(desc(col_attr))
                else:
                    query = query.order_by(asc(col_attr))
                    
            # Apply pagination
            results = query.offset(offset).limit(limit).all()
            
            # Convert SQLAlchemy objects to dicts for UI to consume easily
            # (Prevents DetachedInstanceError since session closes)
            dict_results = []
            for r in results:
                # Copy attributes except internal SQLAlchemy state
                d = {c.name: getattr(r, c.name) for c in r.__table__.columns}
                dict_results.append(d)
                
            return dict_results, total_count
            
        except Exception as e:
            logger.error(f"Error fetching data from {table_name}: {e}")
            return [], 0
        finally:
            db.close()

    @staticmethod
    def update_alert_status(alert_id: int, new_status: str) -> bool:
        """Update an alert's status."""
        db = SessionLocal()
        try:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if alert:
                alert.status = new_status
                db.commit()
                return True
            return False
        except Exception as e:
            logger.error(f"Error updating alert {alert_id}: {e}")
            db.rollback()
            return False
        finally:
            db.close()

    @staticmethod
    def record_report(file_path: str, report_type: str = "Security", report_format: str = "CSV") -> bool:
        db = SessionLocal()
        try:
            db.add(Report(report_type=report_type, file_path=file_path, format=report_format))
            db.commit()
            return True
        except Exception as e:
            logger.error("Error recording report %s: %s", file_path, e)
            db.rollback()
            return False
        finally:
            db.close()
