package bg.wandersnap.config;

import io.github.cdimascio.dotenv.Dotenv;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.thymeleaf.spring6.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.templatemode.TemplateMode;

import java.util.Objects;
import java.util.concurrent.Executor;

@Configuration
class ApplicationBeanConfiguration {
    private static final String CHARACTER_ENCODING = "UTF-8";
    private static final String TEMPLATE_RESOLVER_PREFIX = "classpath:/templates/";
    private static final String TEMPLATE_RESOLVER_SUFFIX = ".html";

    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

    @Bean
    public Validator validator() {
        try (final ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory()) {
            return validatorFactory.getValidator();
        }
    }

    @Bean
    public SpringResourceTemplateResolver templateResolver() {
        final SpringResourceTemplateResolver templateResolver = new SpringResourceTemplateResolver();
        templateResolver.setPrefix(TEMPLATE_RESOLVER_PREFIX);
        templateResolver.setSuffix(TEMPLATE_RESOLVER_SUFFIX);
        templateResolver.setTemplateMode(TemplateMode.HTML);
        templateResolver.setCharacterEncoding(CHARACTER_ENCODING);
        templateResolver.setCacheable(false);
        return templateResolver;
    }

    @Bean
    public Executor executor() {
        final ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(24);
        executor.setMaxPoolSize(32);
        executor.setQueueCapacity(1000);
        executor.setThreadNamePrefix("wander-snap-");
        executor.initialize();
        return executor;
    }

    @Bean
    public Dotenv dotenv() {
        return Dotenv.configure()
                .directory("src/main/resources/env")
                .filename("variables.env")
                .load();
    }

    @Bean
    public TextEncryptor textEncryptor(final Dotenv variableLoader) {

        return Encryptors.delux(
                Objects.requireNonNull(variableLoader.get("REFRESH_TOKEN_ENCRYPTION_PASSWORD")),
                Objects.requireNonNull(variableLoader.get("REFRESH_TOKEN_ENCRYPTION_SALT"))
        );
    }
}