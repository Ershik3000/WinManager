import sys
import os
import zipfile
import shutil
from PyQt6.QtWidgets import (QApplication, QWizard, QWizardPage, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QFileDialog, QSpinBox, QListWidget,
                             QGroupBox, QFormLayout, QCheckBox, QMessageBox,
                             QRadioButton, QWidget, QScrollArea)
from PyQt6.QtCore import Qt, QSettings
from PyQt6.QtGui import QFont

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class EULAPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Лицензионное соглашение")
        self.setSubTitle("Пожалуйста, прочитайте соглашение полностью перед продолжением")
        
        layout = QVBoxLayout()
        
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setPlainText("""ПОЛЬЗОВАТЕЛЬСКОЕ СОГЛАШЕНИЕ (EULA)
Программное обеспечение «Win Manager»
Последнее обновление: 28 мая 2026 года

Пользовательское соглашение является юридически обязательным договором между конечным пользователем и Разработчиком программного обеспечения «Win Manager» (далее — «Правообладатель»).

ВНИМАНИЕ: «Win Manager» является серверным инструментом управления, работающим с правами суперпользователя (root/администратор). Любое неверное действие может привести к полной потере данных или неработоспособности сервера.

Устанавливая, загружая или используя Программное обеспечение (ПО), Вы безоговорочно принимаете условия настоящего Соглашения. Если Вы не согласны с условиями, Вы обязаны прекратить установку и удалить все компоненты ПО.

1. Термины и определения
1.1. Программное обеспечение (ПО) — программа для ЭВМ «Win Manager», включая все ее компоненты, исходный код (если применимо), базы данных и документацию, предназначенная для управления серверной инфраструктурой.
1.2. Сервер — аппаратное или виртуальное устройство, на котором Пользователь разворачивает ПО.
1.3. Root-доступ (Суперпользователь) — уровень привилегий, позволяющий ПО безусловно изменять системные файлы, конфигурации и данные без дополнительного подтверждения.

2. Предмет соглашения и лицензия
2.1. Правообладатель предоставляет Пользователю неисключительное, непередаваемое право на установку и использование ПО на серверах, принадлежащих Пользователю, исключительно для целей администрирования и управления серверной средой.
2.2. Использование ПО допускается только в рамках функциональных возможностей, предусмотренных штатной документацией.
2.3. Пользователь не имеет права:

Распространять, сдавать в аренду или продавать ПО третьим лицам без письменного согласия Правообладателя;

Осуществлять обратную разработку, декомпилировать или модифицировать закрытую часть исходного кода;

Использовать ПО для управления серверами, вовлеченными в противоправную деятельность (DDoS-атаки, рассылка спама, фишинг, распространение вредоносного ПО).

3. Признание рисков и отказ от гарантий (Важные положения)
3.1. Высокий уровень доступа. Пользователь осознает, что ПО функционирует на уровне ядра системы и требует наивысших привилегий. Пользователь принимает на себя все риски, связанные с предоставлением ПО неограниченного доступа к файловой системе, базам данных и сетевым настройкам.
3.2. Отсутствие гарантий. ПО предоставляется по принципу «AS IS» (как есть). Правообладатель не гарантирует:

Отсутствие ошибок в работе ПО (багов);

Бесперебойную и безошибочную работу после автоматических обновлений;

Соответствие ПО специфическим требованиям безопасности конкретной инфраструктуры Пользователя;

Совместимость со всем сторонним программным обеспечением, установленным на Сервере.

4. Ограничение ответственности (Отказ от ответственности — «Окно защиты»)
Данный раздел является существенным условием договора. Пожалуйста, прочтите его внимательно.

4.1. Правообладатель не несет материальной, административной или уголовной ответственности за прямой или косвенный ущерб, причиненный Пользователю или третьим лицам в результате использования или невозможности использования ПО, включая, но не ограничиваясь:

Потерю данных, баз данных, конфигураций сайтов или почтовых серверов;

Выход сервера из строя (отказ в обслуживании);

Упущенную выгоду, потерю клиентов или репутационные потери бизнеса;

Несанкционированный доступ к серверу третьими лицами, произошедший не по прямой вине ПО.

4.2. Пользователь единолично отвечает за создание резервных копий (бэкапов) до начала использования ПО и после каждого сеанса внесения изменений. Функция автоматического бэкапа, если она предусмотрена ПО, не освобождает Пользователя от обязанности самостоятельного контроля сохранности данных.

4.3. В случае возникновения споров, максимальный размер ответственности Правообладателя ограничивается суммой, уплаченной Пользователем за лицензию (или 0 рублей, если ПО используется на безвозмездной основе).

5. Техническая поддержка и данные
5.1. Для корректной работы ПО может собирать анонимизированные технические данные: загрузку ЦП, объем ОЗУ, версию ОС, логи ошибок. Пользователь дает согласие на сбор таких данных для улучшения качества продукта.
5.2. Правообладатель не запрашивает и не хранит персональные данные посетителей сайтов, управляемых сервером.
5.3. Правообладатель оставляет за собой право принудительно прекратить действие лицензии и заблокировать доступ к ПО, если будет обнаружено, что ПО используется для вредоносной активности.

6. Заключительные положения
6.1. Настоящее Соглашение регулируется законодательством юрисдикции, в которой зарегистрирован Правообладатель.
6.2. Правообладатель имеет право вносить изменения в данное Соглашение в одностороннем порядке. Продолжение использования ПО после обновления текста Соглашения означает принятие новых условий.
6.3. Если какое-либо положение данного Соглашения будет признано судом недействительным, это не влияет на действительность остальных положений.

Принимая условия, Вы подтверждаете, что:

Вы являетесь квалифицированным администратором сервера;

Понимаете риски работы с инструментами уровня суперпользователя;

Отказываетесь от претензий к Правообладателю за последствия, вызванные вашими действиями или ошибками в работе ПО.

Для получения разъяснений по условиям Соглашения свяжитесь с нашей службой поддержки.""")
        
        layout.addWidget(self.text_edit)
        
        self.accept_checkbox = QCheckBox("Я прочитал и принимаю условия лицензионного соглашения")
        self.accept_checkbox.stateChanged.connect(self.completeChanged)
        layout.addWidget(self.accept_checkbox)
        
        self.setLayout(layout)
    
    def isComplete(self):
        return self.accept_checkbox.isChecked()

class InstallPathPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Выбор места установки")
        self.setSubTitle("Выберите папку для установки Win Manager")
        
        layout = QVBoxLayout()
        
        path_layout = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        default_path = os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'WinManager')
        self.path_edit.setText(default_path)
        path_layout.addWidget(self.path_edit)
        
        browse_btn = QPushButton("Обзор...")
        browse_btn.clicked.connect(self.browse_path)
        path_layout.addWidget(browse_btn)
        
        layout.addLayout(path_layout)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def browse_path(self):
        path = QFileDialog.getExistingDirectory(self, "Выберите папку установки")
        if path:
            self.path_edit.setText(path)
            self.completeChanged.emit()
    
    def isComplete(self):
        return bool(self.path_edit.text())

class AuthPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Аутентификация")
        self.setSubTitle("Настройка параметров безопасности")
        
        scroll = QScrollArea()
        widget = QWidget()
        layout = QFormLayout()
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Пароль:", self.password_edit)
        
        self.question_edit = QLineEdit()
        layout.addRow("Секретный вопрос:", self.question_edit)
        
        self.answer_edit = QLineEdit()
        self.answer_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addRow("Ответ:", self.answer_edit)
        
        self.max_attempts = QSpinBox()
        self.max_attempts.setRange(1, 100)
        self.max_attempts.setValue(5)
        layout.addRow("Максимум попыток:", self.max_attempts)
        
        self.admin_page = QLineEdit()
        self.admin_page.setPlaceholderText("/admin")
        layout.addRow("Страница администратора:", self.admin_page)
        
        self.admin_user_agent = QLineEdit()
        layout.addRow("Admin User Agent:", self.admin_user_agent)
        
        self.ipv4_admin = QLineEdit()
        layout.addRow("IPv4 администратора:", self.ipv4_admin)
        
        self.ip_admin = QLineEdit()
        layout.addRow("IP администратора:", self.ip_admin)
        
        widget.setLayout(layout)
        scroll.setWidget(widget)
        
        main_layout = QVBoxLayout()
        main_layout.addWidget(scroll)
        self.setLayout(main_layout)

class NetworkPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Сеть")
        self.setSubTitle("Настройка сетевых параметров")
        
        layout = QFormLayout()
        
        self.ports_edit = QLineEdit()
        self.ports_edit.setText("443")
        layout.addRow("Порты:", self.ports_edit)
        
        self.days_spin = QSpinBox()
        self.days_spin.setRange(0, 10000)
        self.days_spin.setValue(100)
        layout.addRow("Лимит в день:", self.days_spin)
        
        self.hours_spin = QSpinBox()
        self.hours_spin.setRange(0, 10000)
        self.hours_spin.setValue(30)
        layout.addRow("Лимит в час:", self.hours_spin)
        
        self.upload_limit = QSpinBox()
        self.upload_limit.setRange(1, 10000)
        self.upload_limit.setValue(100)
        layout.addRow("Лимит загрузки (МБ):", self.upload_limit)
        
        self.setLayout(layout)

class ServersPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Серверы")
        self.setSubTitle("Добавление серверов")
        
        layout = QVBoxLayout()
        
        self.server_list = QListWidget()
        layout.addWidget(self.server_list)
        
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Добавить сервер")
        add_btn.clicked.connect(self.add_server_dialog)
        btn_layout.addWidget(add_btn)
        
        remove_btn = QPushButton("Удалить")
        remove_btn.clicked.connect(self.remove_server)
        btn_layout.addWidget(remove_btn)
        
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)
        self.servers = []
    
    def add_server_dialog(self):
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Добавить сервер")
        
        widget = QWidget()
        layout = QFormLayout()
        
        name_edit = QLineEdit()
        layout.addRow("Имя:", name_edit)
        
        folder_edit = QLineEdit()
        layout.addRow("Папка:", folder_edit)
        
        command_edit = QLineEdit()
        layout.addRow("Команда:", command_edit)
        
        path_edit = QLineEdit()
        layout.addRow("Путь:", path_edit)
        
        widget.setLayout(layout)
        dialog.layout().addWidget(widget, 0, 1)
        
        dialog.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        
        if dialog.exec() == QMessageBox.StandardButton.Ok:
            server_data = {
                'name': name_edit.text(),
                'folder': folder_edit.text(),
                'command': command_edit.text(),
                'path': path_edit.text(),
                'enabled': 'true'
            }
            self.servers.append(server_data)
            self.server_list.addItem(f"{server_data['name']} ({server_data['path']})")

    def remove_server(self):
        current = self.server_list.currentRow()
        if current >= 0:
            self.server_list.takeItem(current)
            del self.servers[current]

class BaseDirPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Папка серверов")
        self.setSubTitle("Укажите папку для серверов")
        
        layout = QVBoxLayout()
        
        path_layout = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setReadOnly(True)
        path_layout.addWidget(self.path_edit)
        
        browse_btn = QPushButton("Обзор...")
        browse_btn.clicked.connect(self.browse_path)
        path_layout.addWidget(browse_btn)
        
        layout.addLayout(path_layout)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def browse_path(self):
        path = QFileDialog.getExistingDirectory(self, "Выберите папку серверов")
        if path:
            self.path_edit.setText(path)
            self.completeChanged.emit()
    
    def isComplete(self):
        return bool(self.path_edit.text())

class WinManagerInstaller(QWizard):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Установщик Win Manager")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.installation_cancelled = False
        
        self.eula_page = EULAPage()
        self.install_path_page = InstallPathPage()
        self.auth_page = AuthPage()
        self.network_page = NetworkPage()
        self.servers_page = ServersPage()
        self.base_dir_page = BaseDirPage()
        
        self.addPage(self.eula_page)
        self.addPage(self.install_path_page)
        self.addPage(self.auth_page)
        self.addPage(self.network_page)
        self.addPage(self.servers_page)
        self.addPage(self.base_dir_page)
        
        self.setButtonText(QWizard.WizardButton.NextButton, "Далее")
        self.setButtonText(QWizard.WizardButton.BackButton, "Назад")
        self.setButtonText(QWizard.WizardButton.CancelButton, "Отмена")
        self.setButtonText(QWizard.WizardButton.FinishButton, "Установить")
        
        self.rejected.connect(self.on_cancel)
        self.button(QWizard.WizardButton.FinishButton).clicked.connect(self.on_finish)
    
    def on_cancel(self):
        self.installation_cancelled = True
        self.reject()
    
    def on_finish(self):
        if not self.installation_cancelled:
            self.perform_installation()
    
    def done(self, result):
        if result == QWizard.DialogCode.Rejected:
            return
        super().done(result)
    
    def generate_config(self):
        config = []
        config.append("[security]")
        config.append(f"PASSWORD = {self.auth_page.password_edit.text()}")
        config.append(f"QUESTION = {self.auth_page.question_edit.text()}")
        config.append(f"ANSWER = {self.auth_page.answer_edit.text()}")
        config.append("BLOCK_TIME = 1800")
        config.append(f"MAX_ATTEMPTS = {self.auth_page.max_attempts.value()}")
        config.append(f"SCAN_THRESHOLD = {self.auth_page.max_attempts.value()}")
        
        admin_page = self.auth_page.admin_page.text() or "/admin"
        config.append(f"ADMINPAGE = {admin_page}")
        
        admin_ua = self.auth_page.admin_user_agent.text() or "null"
        config.append(f"ADMINUserA = {admin_ua}")
        
        ipv4 = self.auth_page.ipv4_admin.text() or "null"
        config.append(f"IPv4ADMIN = {ipv4}")
        
        ip_admin = self.auth_page.ip_admin.text() or "null"
        config.append(f"IPADMIN = {ip_admin}")
        
        config.append("FILEAUTH = 1212/satch.saa")
        config.append("")
        config.append("[network]")
        config.append(f"ports = {self.network_page.ports_edit.text()}")
        
        days = self.network_page.days_spin.value()
        hours = self.network_page.hours_spin.value()
        config.append(f"limits = {days} per day, {hours} per hour")
        
        config.append(f"upload_limit_mb = {self.network_page.upload_limit.value()}")
        config.append("")
        config.append("[servers]")
        config.append(f"count = {len(self.servers_page.servers)}")
        config.append("")
        
        for i, server in enumerate(self.servers_page.servers, 1):
            config.append(f"[server_{i}]")
            config.append(f"name = {server['name']}")
            config.append(f"folder = {server['folder']}")
            config.append(f"command = {server['command']}")
            config.append(f"path = {server['path']}")
            config.append(f"enabled = {server['enabled']}")
            config.append("")
        
        config.append("[paths]")
        config.append(f"base_dir = {self.base_dir_page.path_edit.text()}")
        config.append(f"server_dir = {self.install_path_page.path_edit.text()}")
        
        return "\n".join(config)
    
    def perform_installation(self):
        if self.installation_cancelled:
            return
            
        install_path = self.install_path_page.path_edit.text()
        temp_path = os.path.join(os.environ.get('TEMP', '/tmp'), 'configserver.ini')
        
        try:
            os.makedirs(install_path, exist_ok=True)
            
            config_content = self.generate_config()
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(config_content)
            
            zip_source = resource_path('WinManager.zip')
            
            if os.path.exists(zip_source):
                with zipfile.ZipFile(zip_source, 'r') as zip_ref:
                    zip_ref.extractall(install_path)
            else:
                QMessageBox.warning(self, "Предупреждение", 
                                  "Архив WinManager.zip не найден. Установлены только конфигурационные файлы.")
            
            config_dest = os.path.join(install_path, 'configserver.ini')
            shutil.copy2(temp_path, config_dest)
            
            QMessageBox.information(self, "Установка завершена", 
                                  f"Win Manager успешно установлен в {install_path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка установки", 
                               f"Произошла ошибка при установке: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    
    installer = WinManagerInstaller()
    installer.show()
    
    sys.exit(app.exec())