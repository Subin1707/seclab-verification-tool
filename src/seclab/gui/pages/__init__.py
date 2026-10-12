"""Workbench pages; all results are read-only projections of backend records."""
from .dashboard_page import DashboardPage
from .dynamic_page import DynamicPage
from .codegen_page import CodeGenerationPage
from .formal_page import FormalPage
from .fuzzing_page import FuzzingPage
from .model_page import ModelPage
from .report_page import ReportPage
from .specification_page import SpecificationPage
from .static_page import StaticPage
from .requirements_page import RequirementsPage
from .source_page import SourcePage
from .stages_page import StagesPage
from .settings_page import SettingsPage
from .sections import AccuracyPage, EvidencePage, HistoryPage, ResultsPage, TraceabilityPage

__all__ = ["DashboardPage", "DynamicPage", "CodeGenerationPage", "FormalPage", "FuzzingPage", "ModelPage",
           "ReportPage", "RequirementsPage", "SettingsPage", "SourcePage", "StagesPage",
           "SpecificationPage", "StaticPage", "AccuracyPage", "EvidencePage", "HistoryPage",
           "ResultsPage", "TraceabilityPage"]
