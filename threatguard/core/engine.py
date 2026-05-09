

from __future__ import annotations

import os
import time
from enum import Enum, auto
from typing import Optional

from PySide6.QtCore import QObject, Signal, QElapsedTimer

from threatguard.core.mock_capture import MockCaptureThread
from threatguard.core.real_capture import RealCaptureThread
from threatguard.core.packet import Packet

class EngineState(Enum):
    STOPPED = auto()
    RUNNING = auto()
    DISABLED = auto()                                       

class CaptureMode(Enum):
    MOCK = auto()
    REAL = auto()

AVAILABLE_MODELS = [
    "XGBoost",
    "Random Forest",
    "Neural Network (LSTM)",
    "Support Vector Machine",
    "Ensemble (Stacking)",
    "Gradient Boosting",
    "Isolation Forest",
]

class IDPSEngine(QObject):
    

             
    state_changed = Signal(EngineState)
    packet_received = Signal(object)                
    packet_blocked = Signal(object)                          
    stats_updated = Signal(dict)                       
    capture_error = Signal(str)                                            

    _PROJECT_DIR = os.path.dirname(os.path.dirname(__file__))
    MODEL_SEARCH_DIRS = [
        os.path.join(_PROJECT_DIR, "models final"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._state = EngineState.STOPPED
        self._capture_thread = None
        self._current_model = AVAILABLE_MODELS[0]
        self._uptime_timer = QElapsedTimer()
        self._capture_mode = CaptureMode.REAL                                                     
        self._test_mode = False
        self._sensitivity_profile = "Balanced"

                                                        
        self._binary_model_path: Optional[str] = None
        self._attack_model_path: Optional[str] = None
        self._scaler_path: Optional[str] = None
        self._label_encoder_path: Optional[str] = None
        self._feature_names_path: Optional[str] = None

                                            
        self._interface: Optional[str] = None

               
        self._total_packets = 0
        self._malicious_packets = 0
        self._blocked_packets = 0
        self._blocked_alert_window_seconds = 15.0
        self._last_block_alert_time: dict[tuple[str, str], float] = {}

                                      
        self._auto_load_models()

                                                                

    @property
    def state(self) -> EngineState:
        return self._state

    @property
    def current_model(self) -> str:
        return self._current_model

    @property
    def capture_mode(self) -> CaptureMode:
        return self._capture_mode

    @property
    def is_running(self) -> bool:
        return self._state in (EngineState.RUNNING, EngineState.DISABLED)

    @property
    def uptime_seconds(self) -> float:
        if self._uptime_timer.isValid():
            return self._uptime_timer.elapsed() / 1000.0
        return 0.0

    @property
    def stats(self) -> dict:
        return {
            "total_packets": self._total_packets,
            "malicious_packets": self._malicious_packets,
            "blocked_packets": self._blocked_packets,
            "uptime": self.uptime_seconds,
            "model": self._current_model,
            "state": self._state,
            "capture_mode": self._capture_mode.name,
        }

                                                                

    def set_capture_mode(self, mode: CaptureMode):
        
        if self.is_running:
            return                              
        self._capture_mode = mode

    def set_interface(self, interface: str):
        
        self._interface = interface or None

    def set_test_mode(self, enabled: bool):
        
        if self.is_running:
            return
        self._test_mode = bool(enabled)

    def set_sensitivity_profile(self, profile: str):
        self._sensitivity_profile = profile
        if self._capture_thread and isinstance(self._capture_thread, RealCaptureThread):
            self._capture_thread.set_sensitivity_profile(profile)

    def set_binary_model_path(self, path: str):
        
        self._binary_model_path = path
        if self._capture_thread and isinstance(self._capture_thread, RealCaptureThread):
            self._capture_thread.set_binary_model(path)

    def set_attack_model_path(self, path: str):
        
        self._attack_model_path = path
        if self._capture_thread and isinstance(self._capture_thread, RealCaptureThread):
            self._capture_thread.set_attack_model(path)

                                                                

    def start(self):
        
        if self.is_running:
            return

                                                                        

        if self._capture_mode == CaptureMode.REAL:
            self._capture_thread = RealCaptureThread(
                interface=self._interface,
                binary_model_path=self._binary_model_path,
                attack_model_path=self._attack_model_path,
                scaler_path=self._scaler_path,
                label_encoder_path=self._label_encoder_path,
                feature_names_path=self._feature_names_path,
                model_name=self._current_model,
                sensitivity_profile=self._sensitivity_profile,
                test_mode=self._test_mode,
                parent=None,
            )
            self._capture_thread.capture_error.connect(self._on_capture_error)
        else:
            self._capture_thread = MockCaptureThread(
                model_name=self._current_model,
                binary_model_path=self._binary_model_path,
                attack_model_path=self._attack_model_path,
                scaler_path=self._scaler_path,
                label_encoder_path=self._label_encoder_path,
                feature_names_path=self._feature_names_path,
            )

        self._capture_thread.packet_captured.connect(self._on_packet_captured)
        self._capture_thread.finished.connect(self._on_capture_thread_finished)
        self._capture_thread.start()

        self._uptime_timer.start()
        self._set_state(EngineState.RUNNING)

    def stop(self):
        
        if not self.is_running:
            return

        if self._capture_thread:
            self._capture_thread.stop()
            self._capture_thread.wait(3000)
            try:
                self._capture_thread.packet_captured.disconnect(self._on_packet_captured)
            except RuntimeError:
                pass
            try:
                self._capture_thread.finished.disconnect(self._on_capture_thread_finished)
            except RuntimeError:
                pass
            if isinstance(self._capture_thread, RealCaptureThread):
                try:
                    self._capture_thread.capture_error.disconnect(self._on_capture_error)
                except RuntimeError:
                    pass
            self._capture_thread = None

        self._uptime_timer.invalidate()
        self._set_state(EngineState.STOPPED)

    def set_model(self, model_name: str):
        
        self._current_model = model_name
        if self._capture_thread:
            self._capture_thread.set_model(model_name)

    def toggle_prevention(self, enabled: bool):
        
        if self._capture_thread:
            self._capture_thread.set_prevention(enabled)

        if enabled and self.is_running:
            self._set_state(EngineState.RUNNING)
        elif not enabled and self.is_running:
            self._set_state(EngineState.DISABLED)

                                                                

    def _auto_load_models(self):
        stage1_names = ("stage1_nids_model.pkl",)
        stage2_names = ("stage2_nids_model.pkl",)

        for model_dir in self.MODEL_SEARCH_DIRS:
            if not os.path.isdir(model_dir):
                continue

            if self._binary_model_path is None:
                for name in stage1_names:
                    candidate = os.path.join(model_dir, name)
                    if os.path.isfile(candidate):
                        self._binary_model_path = candidate
                        break

            if self._attack_model_path is None:
                for name in stage2_names:
                    candidate = os.path.join(model_dir, name)
                    if os.path.isfile(candidate):
                        self._attack_model_path = candidate
                        break

            if self._scaler_path is None:
                scaler = os.path.join(model_dir, "scaler.pkl")
                if os.path.isfile(scaler):
                    self._scaler_path = scaler

            if self._label_encoder_path is None:
                label_encoder = os.path.join(model_dir, "label_encoder.pkl")
                if os.path.isfile(label_encoder):
                    self._label_encoder_path = label_encoder

            if self._feature_names_path is None:
                feature_names = os.path.join(model_dir, "feature_names.pkl")
                if os.path.isfile(feature_names):
                    self._feature_names_path = feature_names

    def _set_state(self, state: EngineState):
        self._state = state
        self.state_changed.emit(state)

    def _on_packet_captured(self, packet: Packet):
        
        self._total_packets += 1

        if packet.is_malicious:
            self._malicious_packets += 1

        if packet.is_blocked:
            if self._should_emit_block_alert(packet):
                self._blocked_packets += 1
                self.packet_blocked.emit(packet)

        self.packet_received.emit(packet)
        self.stats_updated.emit(self.stats)

    def _should_emit_block_alert(self, packet: Packet) -> bool:
        
        key = (packet.src_ip, packet.threat_type.name)
        now = time.monotonic()
        last_seen = self._last_block_alert_time.get(key)
        if last_seen is not None and (now - last_seen) < self._blocked_alert_window_seconds:
            return False
        self._last_block_alert_time[key] = now
        return True

    def _on_capture_error(self, error_msg: str):
        
        self.capture_error.emit(error_msg)
        if self.is_running:
            self.stop()

    def _on_capture_thread_finished(self):
        
        if self.is_running:
            self._uptime_timer.invalidate()
            self._set_state(EngineState.STOPPED)
