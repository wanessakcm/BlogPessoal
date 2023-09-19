package com.generation.blogpessoal.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Entity//define como uma entidade/tabela
@Table(name="tb_usuarios")
public class Usuario {
	
	@Id
	@GeneratedValue(strategy=GenerationType.IDENTITY)//autoincrement 
	private Long id;
	
	@NotBlank(message="O atributo nome é obrigatório")
	private String nome;
	
	@Schema(example = "email@email.com.br")
	@NotBlank(message="O atributo usuário é obrigatório")
	@Email(message="O atributo usuário tem que receber um email válido")
	private String usuario;
	
	@NotBlank(message="O atributo senha é obrigatório")
	@Size(min=8, message= "A senha tem que ter no mínimo 8 caracteres")
	private String senha;
	
	@Size(max=4000, message="O link da foto inserida não pode passar dos 4000 cacacteres")
	private String foto;
	
	@OneToMany(fetch = FetchType.LAZY,mappedBy="usuario",cascade=CascadeType.REMOVE)
	@JsonIgnoreProperties("usuario")
	private List<Postagem> postagem;
	
	public Usuario(Long id, String nome, String usuario, String senha, String foto, List<Postagem> postagem) {
		this.id = id;
		this.nome = nome;
		this.usuario = usuario;
		this.senha = senha;
		this.foto = foto;
		this.postagem = postagem;
	}
	
	public Usuario() { }

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public String getUsuario() {
		return usuario;
	}

	public void setUsuario(String usuario) {
		this.usuario = usuario;
	}

	public String getSenha() {
		return senha;
	}

	public void setSenha(String senha) {
		this.senha = senha;
	}

	public String getFoto() {
		return foto;
	}

	public void setFoto(String foto) {
		this.foto = foto;
	}

	public List<Postagem> getPostagem() {
		return postagem;
	}

	public void setPostagem(List<Postagem> postagem) {
		this.postagem = postagem;
	}

	
}
