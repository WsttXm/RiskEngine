package org.wstt.riskengineserver.service;

import org.springframework.stereotype.Service;
import org.wstt.riskengineserver.entity.App;
import org.wstt.riskengineserver.repository.AppRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * 接入应用管理服务
 */
@Service
public class AppService {

    private final AppRepository appRepository;
    private final EncryptionService encryptionService;

    public AppService(AppRepository appRepository, EncryptionService encryptionService) {
        this.appRepository = appRepository;
        this.encryptionService = encryptionService;
    }

    public List<App> findAll() {
        return appRepository.findAll();
    }

    public Optional<App> findById(Long id) {
        return appRepository.findById(id);
    }

    public Optional<App> findByAppKey(String appKey) {
        return appRepository.findByAppKey(appKey);
    }

    /**
     * 创建新应用, 自动生成appKey和加密密钥
     */
    public App createApp(String appName) {
        App app = new App();
        app.setAppName(appName);
        app.setAppKey(UUID.randomUUID().toString().replace("-", ""));
        app.setEncryptionKey(encryptionService.generateKey());
        return appRepository.save(app);
    }

    public App save(App app) {
        return appRepository.save(app);
    }

    public void deleteById(Long id) {
        appRepository.deleteById(id);
    }

    /**
     * 重新生成应用的加密密钥
     */
    public App regenerateEncryptionKey(Long id) {
        App app = appRepository.findById(id).orElseThrow();
        app.setEncryptionKey(encryptionService.generateKey());
        return appRepository.save(app);
    }
}
