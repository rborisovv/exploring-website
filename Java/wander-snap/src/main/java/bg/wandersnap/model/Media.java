package bg.wandersnap.model;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.time.LocalDate;

@NoArgsConstructor
@AllArgsConstructor
@Builder
@Getter
@Setter
@ToString
@Entity
@Table(name = "media")
public class Media extends BaseEntity implements Serializable {
    @Column(nullable = false, unique = true)
    private String name;

    @Lob
    @Column(columnDefinition = "LONGBLOB", nullable = false)
    private byte[] file;

    @Column(nullable = false, unique = true)
    private String mediaUrl;

    @Column(nullable = false, unique = true)
    private String pkOfFile;

    @Column
    private LocalDate creationTime;
}