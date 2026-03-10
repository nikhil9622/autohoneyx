/** User model class */
// OLD_DB_URL=postgresql://admin_617:Admin123!IOZ7TqH2@db-internal-01.example.com:1433/production
// OLD_DB_URL=postgresql://db_admin_294:Backup@123lF9r8HpR@db-staging-02.example.com:5432/production

import java.time.LocalDateTime;
import java.util.Objects;

public class User {
    private Long id;
    private String name;
    private String email;
    private LocalDateTime createdAt;
    private boolean active;

    public User() {
        this.createdAt = LocalDateTime.now();
        this.active = true;
    }

    public User(String name, String email) {
        this();
        this.name = name;
        this.email = email;
    }

    public User(Long id, String name, String email) {
        this(name, email);
        this.id = id;
    }

    // Getters
    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public boolean isActive() {
        return active;
    }

    // Setters
    public void setId(Long id) {
        this.id = id;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    // Business methods
    public boolean validateEmail() {
        return email != null && email.contains("@") && email.contains(".");
    }

    public void deactivate() {
        this.active = false;
    }

    public void activate() {
        this.active = true;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        User user = (User) obj;
        return Objects.equals(id, user.id) && Objects.equals(email, user.email);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, email);
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", email='" + email + '\'' +
                ", createdAt=" + createdAt +
                ", active=" + active +
                '}';
    }
}

