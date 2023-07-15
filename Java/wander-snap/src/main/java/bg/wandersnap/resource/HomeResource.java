package bg.wandersnap.resource;

import bg.wandersnap.domain.HttpGenericResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashSet;

@RestController
public class HomeResource {

    @GetMapping("/hello")
    public ResponseEntity<HttpGenericResponse> hello() {
        HttpGenericResponse hello = new HttpGenericResponse("Hello", new HashSet<>());

        return new ResponseEntity<>(hello, HttpStatus.OK);
    }
}